#pragma once

namespace Dumper
{
	class c_live_enricher
	{
	public:
		struct attach_info_t
		{
			DWORD m_pid = 0;
			std::filesystem::path m_image_path{};
			std::string m_process_name{};
		};

		// Find a running process by exe name and resolve its on-disk image path.
		[[nodiscard]] static bool resolve_running_image(
			const std::string& process_name,
			attach_info_t& out)
		{
			out = {};
			out.m_process_name = process_name;
			out.m_pid = find_process_id(process_name);
			if (!out.m_pid)
			{
				Logger::error("[c_live_enricher] resolve_running_image: process not found");
				return false;
			}

			HANDLE process = OpenProcess(
				PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
				FALSE,
				out.m_pid);
			if (!process)
			{
				char buf[160]{};
				::snprintf(buf, sizeof(buf),
					"[c_live_enricher] resolve_running_image: OpenProcess failed (%lu)", GetLastError());
				Logger::error(buf);
				return false;
			}

			std::wstring wide(MAX_PATH * 4, L'\0');
			DWORD wide_n = static_cast<DWORD>(wide.size());
			std::filesystem::path path;

			if (QueryFullProcessImageNameW(process, 0, wide.data(), &wide_n) && wide_n)
			{
				wide.resize(wide_n);
				path = wide;
			}
			else
			{
				wchar_t module_path[MAX_PATH * 4]{};
				if (GetModuleFileNameExW(process, nullptr, module_path, static_cast<DWORD>(std::size(module_path))))
					path = module_path;
			}

			CloseHandle(process);

			if (path.empty() || !std::filesystem::exists(path))
			{
				Logger::error("[c_live_enricher] resolve_running_image: could not resolve image path");
				return false;
			}

			out.m_image_path = std::filesystem::weakly_canonical(path);
			Logger::print("[c_live_enricher] resolve_running_image: pid=%lu path=%s",
				out.m_pid, out.m_image_path.string().c_str());
			return true;
		}

		[[nodiscard]] bool enrich(
			Types::dump_result_t& result,
			const std::filesystem::path& out_dir,
			std::string process_name = {})
		{
			if (process_name.empty())
			{
				if (!result.m_target.m_default_process.empty())
					process_name = result.m_target.m_default_process;
				else
				{
					Logger::warn("[c_live_enricher] enrich: no process name provided");
					return false;
				}
			}

			Logger::print("[c_live_enricher] enrich: attaching to %s", process_name.c_str());

			const auto pid = find_process_id(process_name);
			if (!pid)
			{
				Logger::warn("[c_live_enricher] enrich: process not found (static dump still valid)");
				return false;
			}

			HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
			if (!process)
			{
				char buf[128]{};
				::snprintf(buf, sizeof(buf), "[c_live_enricher] enrich: OpenProcess failed (%lu)", GetLastError());
				Logger::warn(buf);
				return false;
			}

			const auto module_base = find_module_base(process, process_name);
			if (!module_base)
			{
				Logger::warn("[c_live_enricher] enrich: module base not found");
				CloseHandle(process);
				return false;
			}

			Logger::print("[c_live_enricher] enrich: pid=%lu base=0x%08X", pid, module_base);

			const auto image_base = result.m_image_base ? result.m_image_base : 0x400000u;
			std::ofstream out(out_dir / "live_snapshot.txt");
			if (!out)
			{
				CloseHandle(process);
				return false;
			}

			out << "live snapshot\n";
			out << "process: " << process_name << "\n";
			out << "pid: " << pid << "\n";
			out << "module_base: 0x" << std::hex << module_base << std::dec << "\n";
			out << "image_base: 0x" << std::hex << image_base << std::dec << "\n\n";

			std::unordered_map<std::uint32_t, std::size_t> vftable_to_class;
			for (std::size_t i = 0; i < result.m_classes.size(); ++i)
			{
				if (result.m_classes[i].m_vftable_va)
					vftable_to_class.emplace(result.m_classes[i].m_vftable_va, i);
			}

			classify_globals_live(process, module_base, image_base, result, vftable_to_class);

			// Walk offsets: prefer already-discovered members; otherwise probe/bootstrap,
			// and only publish into the SDK after the walk validates.
			const auto entity_prop_off = discover_or_bootstrap(result, "VuEntity", "properties", 0x44);
			const auto entity_comp_off = discover_or_bootstrap(result, "VuEntity", "component_list", 0x48);
			const auto entity_xf_off = discover_or_bootstrap(result, "VuEntity", "transform", 0x50);
			const auto entity_next_off = discover_or_bootstrap(result, "VuEntity", "bucket_next", 0x58);
			const auto repo_buckets_off = discover_or_bootstrap(result, "VuEntityRepositoryImpl", "buckets", 0x0C);
			const auto repo_count_off = discover_or_bootstrap(result, "VuEntityRepositoryImpl", "entity_count", 0x40C);
			const auto comp_prop_off = discover_or_bootstrap(result, "VuComponent", "properties", 0x04);
			const auto comp_next_off = discover_or_bootstrap(result, "VuComponent", "next", 0x0C);

			const auto repo_rva = find_global_rva(result, "VuEntityRepositoryImpl");
			const auto boat_rva = find_global_rva(result, "VuBoatManager");

			live_fingerprint_db_t fingerprints{};
			ptr_vote_db_t ptr_votes{};

			std::uint32_t repo = 0;
			if (repo_rva)
				(void)read_u32(process, module_base + repo_rva, repo);
			out << "g_vu_entity_repository rva=0x" << std::hex << repo_rva
				<< " value=0x" << repo << std::dec << "\n";

			std::size_t rebound = 0;
			std::size_t entities_seen = 0;
			bool layout_validated = false;

			if (repo && repo_buckets_off)
			{
				std::uint32_t entity_count = 0;
				if (repo_count_off)
					(void)read_u32(process, repo + repo_count_off, entity_count);
				out << "entity_count=" << entity_count << "\n\n";

				for (std::uint32_t bucket = 0; bucket < 256; ++bucket)
				{
					std::uint32_t entity = 0;
					if (!read_u32(process, repo + repo_buckets_off + bucket * 4, entity))
						continue;

					while (entity)
					{
						++entities_seen;
						const auto before = rebound;
						rebound += rebind_owner_properties(
							process, module_base, image_base, entity, entity_prop_off,
							result, vftable_to_class, fingerprints, out);
						if (rebound > before)
							layout_validated = true;

						// Sample typed pointer recovery on early entities + periodically.
						if (entities_seen <= 64 || (entities_seen % 16) == 0)
						{
							collect_typed_pointer_votes(
								process, module_base, image_base, entity, result, vftable_to_class, ptr_votes);
						}

						std::uint32_t component = 0;
						if (entity_comp_off)
							(void)read_u32(process, entity + entity_comp_off, component);
						for (int cguard = 0; component && cguard < 64; ++cguard)
						{
							rebound += rebind_owner_properties(
								process, module_base, image_base, component, comp_prop_off,
								result, vftable_to_class, fingerprints, out);
							collect_typed_pointer_votes(
								process, module_base, image_base, component, result, vftable_to_class, ptr_votes);
							std::uint32_t cnext = 0;
							if (!comp_next_off || !read_u32(process, component + comp_next_off, cnext))
								break;
							component = cnext;
						}

						std::uint32_t transform = 0;
						if (entity_xf_off)
							(void)read_u32(process, entity + entity_xf_off, transform);
						if (transform)
						{
							// Transform is a small layout object — rebind Position/Rotation/Scale only.
							// Do NOT pointer-scan it; that reads past the object into heap noise.
							rebound += rebind_owner_properties(
								process, module_base, image_base, transform, comp_prop_off,
								result, vftable_to_class, fingerprints, out);

							const auto* xf = find_class_mut(result, "VuTransformComponent");
							std::uint32_t pos_off = 0;
							std::uint32_t scale_off = 0;
							if (xf)
							{
								if (const auto* p = find_prop(*xf, "Position"))
									pos_off = p->m_offset;
								if (const auto* p = find_prop(*xf, "Scale"))
									scale_off = p->m_offset;
							}

							float pos[3]{};
							float scale[3]{};
							if (pos_off)
								(void)read_bytes(process, transform + pos_off, pos, sizeof(pos));
							if (scale_off)
								(void)read_bytes(process, transform + scale_off, scale, sizeof(scale));

							if (entities_seen <= 32)
							{
								out << "entity[" << entities_seen << "] 0x" << std::hex << entity
									<< " transform=0x" << transform << std::dec;
								if (pos_off)
									out << " pos=(" << pos[0] << "," << pos[1] << "," << pos[2] << ")";
								if (scale_off)
									out << " scale=(" << scale[0] << "," << scale[1] << "," << scale[2] << ")";
								out << "\n";
							}
						}

						std::uint32_t next = 0;
						if (!entity_next_off || !read_u32(process, entity + entity_next_off, next))
							break;
						entity = next;
					}
				}
			}

			if (layout_validated)
			{
				publish_field(result, "VuEntityRepositoryImpl", "buckets", repo_buckets_off,
					Types::property_kind_t::pointer, "VuEntity");
				publish_field(result, "VuEntityRepositoryImpl", "entity_count", repo_count_off,
					Types::property_kind_t::int32);
				publish_field(result, "VuEntity", "properties", entity_prop_off,
					Types::property_kind_t::pointer, "VuProperty");
				publish_field(result, "VuEntity", "component_list", entity_comp_off,
					Types::property_kind_t::pointer, "VuComponent");
				publish_field(result, "VuEntity", "transform", entity_xf_off,
					Types::property_kind_t::pointer, "VuTransformComponent");
				publish_field(result, "VuEntity", "bucket_next", entity_next_off,
					Types::property_kind_t::pointer, "VuEntity");
				publish_field(result, "VuComponent", "properties", comp_prop_off,
					Types::property_kind_t::pointer, "VuProperty");
				publish_field(result, "VuComponent", "next", comp_next_off,
					Types::property_kind_t::pointer, "VuComponent");
			}

			std::uint32_t boat_manager = 0;
			if (boat_rva)
				(void)read_u32(process, module_base + boat_rva, boat_manager);
			out << "\ng_vu_boat_manager rva=0x" << std::hex << boat_rva
				<< " value=0x" << boat_manager << std::dec << "\n";
			if (boat_manager)
			{
				const auto boats_data_off = discover_or_bootstrap(result, "VuBoatManager", "boats_data", 0x0C);
				const auto boats_count_off = discover_or_bootstrap(result, "VuBoatManager", "boats_count", 0x10);
				std::uint32_t boats_data = 0;
				std::uint32_t boats_count = 0;
				(void)read_u32(process, boat_manager + boats_data_off, boats_data);
				(void)read_u32(process, boat_manager + boats_count_off, boats_count);
				out << "boats_data=0x" << std::hex << boats_data << std::dec
					<< " boats_count=" << boats_count << "\n";
				if (boats_count > 0 && boats_count < 1024 && boats_data)
				{
					publish_field(result, "VuBoatManager", "boats_data", boats_data_off,
						Types::property_kind_t::pointer, "VuBoatEntity");
					publish_field(result, "VuBoatManager", "boats_count", boats_count_off,
						Types::property_kind_t::int32);

					for (std::uint32_t i = 0; i < boats_count && i < 64; ++i)
					{
						std::uint32_t boat = 0;
						if (!read_u32(process, boats_data + i * 4, boat) || !boat)
							continue;
						rebound += rebind_owner_properties(
							process, module_base, image_base, boat, entity_prop_off,
							result, vftable_to_class, fingerprints, out);
						collect_typed_pointer_votes(
							process, module_base, image_base, boat, result, vftable_to_class, ptr_votes);
					}
				}
			}

			const auto typed_ptrs = commit_typed_pointer_votes(result, ptr_votes, out);
			strip_spurious_layout_pointers(result);

			const auto orphans_assigned = assign_orphans_by_fingerprint(result, fingerprints, out);

			// Drop any leftover seeded placeholders before emit.
			strip_engine_model_placeholders(result);

			if (is_hydro_thunder(result.m_target))
				capture_live_cameras(process, module_base, result, out);

			result.m_live_rebound_count = rebound;
			result.m_live_orphan_assigned = orphans_assigned;
			out << "\nentities_seen=" << entities_seen << "\n";
			out << "properties_rebound=" << rebound << "\n";
			out << "typed_pointers=" << typed_ptrs << "\n";
			out << "fingerprint_classes=" << fingerprints.m_names.size() << "\n";
			out << "orphans_assigned=" << orphans_assigned << "\n";
			out << "live_cameras=" << result.m_live_cameras.size() << "\n";

			CloseHandle(process);
			Logger::print("[c_live_enricher] enrich: entities=%zu rebound=%zu orphans=%zu typed=%zu cameras=%zu",
				entities_seen, rebound, orphans_assigned, typed_ptrs, result.m_live_cameras.size());
			return true;
		}

	private:
		struct live_fingerprint_db_t
		{
			// class_index -> live property names
			std::unordered_map<std::size_t, std::unordered_set<std::string>> m_names{};
			// class_index -> name -> offset
			std::unordered_map<std::size_t, std::unordered_map<std::string, std::uint32_t>> m_offsets{};
			// distinctive name -> classes that own it (for uniqueness scoring)
			std::unordered_map<std::string, std::unordered_set<std::size_t>> m_name_owners{};
			std::size_t m_assigned = 0;
		};

		static void classify_globals_live(
			HANDLE process,
			std::uint32_t module_base,
			std::uint32_t image_base,
			Types::dump_result_t& result,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class)
		{
			std::unordered_map<std::uint32_t, std::size_t> td_to_class;
			for (std::size_t i = 0; i < result.m_classes.size(); ++i)
			{
				if (result.m_classes[i].m_type_descriptor_va)
					td_to_class.emplace(result.m_classes[i].m_type_descriptor_va, i);
			}

			for (auto& g : result.m_globals)
			{
				if (!g.m_rva)
					continue;

				std::uint32_t instance = 0;
				if (!read_u32(process, module_base + g.m_rva, instance) || !instance)
					continue;

				std::uint32_t vftable = 0;
				if (!read_u32(process, instance, vftable) || !vftable)
					continue;

				std::uint32_t vftable_va = vftable;
				if (vftable >= module_base)
					vftable_va = image_base + (vftable - module_base);

				std::size_t class_index = static_cast<std::size_t>(-1);
				if (auto it = vftable_to_class.find(vftable_va); it != vftable_to_class.end())
				{
					class_index = it->second;
				}
				else
				{
					// Primary/secondary vftable mismatch: resolve via COL -> type_descriptor.
					std::uint32_t col = 0;
					if (vftable >= 4 && read_u32(process, vftable - 4, col) && col)
					{
						std::uint32_t td = 0;
						if (read_u32(process, col + 0x0C, td) && td)
						{
							std::uint32_t td_va = td;
							if (td >= module_base)
								td_va = image_base + (td - module_base);
							if (auto td_it = td_to_class.find(td_va); td_it != td_to_class.end())
								class_index = td_it->second;
						}
					}
				}

				if (class_index == static_cast<std::size_t>(-1))
					continue;

				const auto& cls = result.m_classes[class_index];
				g.m_class_name = cls.m_name;
				g.m_vftable_va = cls.m_vftable_va ? cls.m_vftable_va : vftable_va;
				g.m_name = "g_" + Common::to_lower(Common::sanitize_identifier(cls.m_name));
				if (g.m_source.find("live_vftable") == std::string::npos)
					g.m_source += "+live_vftable";
			}

			for (auto& g : result.m_globals)
			{
				if (g.m_class_name == "VuEntityRepositoryImpl")
					g.m_name = "g_vu_entity_repository";
				else if (g.m_class_name == "VuBoatManager")
					g.m_name = "g_vu_boat_manager";
				else if (g.m_class_name == "VuProjectManager")
					g.m_name = "g_vu_project_manager";
				else if (g.m_class_name == "VuGameModeManagerImpl")
					g.m_name = "g_vu_game_mode_manager";
				else if (g.m_class_name == "VuDevMenu")
					g.m_name = "g_vu_dev_menu";
			}
		}

		[[nodiscard]] static std::uint32_t find_global_rva(const Types::dump_result_t& result, std::string_view class_name)
		{
			for (const auto& g : result.m_globals)
			{
				if (g.m_class_name == class_name && g.m_rva)
					return g.m_rva;
			}
			return 0;
		}

		[[nodiscard]] static Types::class_info_t* find_class_mut(Types::dump_result_t& result, std::string_view name)
		{
			for (auto& cls : result.m_classes)
			{
				if (cls.m_name == name)
					return &cls;
			}
			return nullptr;
		}

		[[nodiscard]] static const Types::property_info_t* find_prop(const Types::class_info_t& cls, std::string_view name)
		{
			const auto want = Common::sanitize_identifier(std::string(name));
			for (const auto& prop : cls.m_properties)
			{
				if (prop.m_offset == 0)
					continue;
				if (prop.m_name == name || prop.m_sanitized_name == want
					|| Common::to_lower(prop.m_sanitized_name) == Common::to_lower(want))
				{
					return &prop;
				}
			}
			return nullptr;
		}

		[[nodiscard]] static std::uint32_t discover_or_bootstrap(
			const Types::dump_result_t& result,
			std::string_view class_name,
			std::string_view field_name,
			std::uint32_t bootstrap)
		{
			for (const auto& cls : result.m_classes)
			{
				if (cls.m_name != class_name)
					continue;
				if (const auto* p = find_prop(cls, field_name))
					return p->m_offset;
			}
			return bootstrap;
		}

		static void publish_field(
			Types::dump_result_t& result,
			std::string_view class_name,
			std::string_view field_name,
			std::uint32_t offset,
			Types::property_kind_t kind,
			std::string_view pointee_class = {})
		{
			if (!offset && kind != Types::property_kind_t::bool8)
				return;
			auto* cls = find_class_mut(result, class_name);
			if (!cls)
				return;

			const auto sanitized = Common::sanitize_identifier(std::string(field_name));
			for (auto& prop : cls->m_properties)
			{
				if (prop.m_name == field_name || prop.m_sanitized_name == sanitized)
				{
					prop.m_offset = offset;
					prop.m_kind = kind;
					prop.m_from_engine_model = false;
					if (!pointee_class.empty())
						prop.m_pointee_class = std::string(pointee_class);
					return;
				}
			}

			Types::property_info_t prop{};
			prop.m_name = std::string(field_name);
			prop.m_sanitized_name = sanitized;
			prop.m_offset = offset;
			prop.m_kind = kind;
			prop.m_from_engine_model = false;
			if (!pointee_class.empty())
				prop.m_pointee_class = std::string(pointee_class);
			cls->m_properties.push_back(std::move(prop));
			std::sort(cls->m_properties.begin(), cls->m_properties.end(),
				[](const Types::property_info_t& a, const Types::property_info_t& b)
				{
					if (a.m_offset != b.m_offset)
						return a.m_offset < b.m_offset;
					return a.m_name < b.m_name;
				});
		}

		[[nodiscard]] static std::size_t resolve_class_index(
			HANDLE process,
			std::uint32_t module_base,
			std::uint32_t image_base,
			std::uint32_t object,
			const Types::dump_result_t& result,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class)
		{
			std::uint32_t vftable = 0;
			if (!read_u32(process, object, vftable) || !vftable)
				return static_cast<std::size_t>(-1);

			std::uint32_t vftable_va = vftable;
			if (vftable >= module_base)
				vftable_va = image_base + (vftable - module_base);

			if (auto it = vftable_to_class.find(vftable_va); it != vftable_to_class.end())
				return it->second;

			std::uint32_t col = 0;
			if (vftable < 4 || !read_u32(process, vftable - 4, col) || !col)
				return static_cast<std::size_t>(-1);

			std::uint32_t td = 0;
			if (!read_u32(process, col + 0x0C, td) || !td)
				return static_cast<std::size_t>(-1);

			std::uint32_t td_va = td;
			if (td >= module_base)
				td_va = image_base + (td - module_base);

			for (std::size_t i = 0; i < result.m_classes.size(); ++i)
			{
				if (result.m_classes[i].m_type_descriptor_va == td_va)
					return i;
			}
			return static_cast<std::size_t>(-1);
		}

		struct ptr_vote_db_t
		{
			// owner_class -> offset -> (pointee_class -> count)
			std::unordered_map<std::size_t, std::unordered_map<std::uint32_t, std::unordered_map<std::string, std::uint32_t>>> m_votes{};
			// owner_class -> offset -> times a non-null candidate was observed
			std::unordered_map<std::size_t, std::unordered_map<std::uint32_t, std::uint32_t>> m_seen{};
			// owner_class -> instances scanned
			std::unordered_map<std::size_t, std::uint32_t> m_instances{};
		};

		[[nodiscard]] static bool is_interesting_pointee(std::string_view class_name)
		{
			if (class_name.empty())
				return false;
			if (Common::starts_with(class_name, "loader_"))
				return false;
			if (class_name.find("?$") != std::string::npos)
				return false;
			// Prefer concrete Vu* engine types (skip ultra-generic bases).
			if (class_name == "VuRefObj" || class_name == "VuBaseObj" || class_name == "VuProperty")
				return false;
			return Common::starts_with(class_name, "Vu");
		}

		// Small layout/math components — pointer-scanning past validated fields is almost always heap noise.
		[[nodiscard]] static bool is_layout_only_class(std::string_view class_name)
		{
			return class_name == "VuTransformComponent"
				|| class_name == "Vu2dLayoutComponent"
				|| class_name == "Vu3dLayoutComponent"
				|| class_name == "VuComponent"
				|| class_name == "VuProperty"
				|| class_name == "VuRefObj"
				|| class_name == "VuBaseObj";
		}

		[[nodiscard]] static std::uint32_t trusted_scan_end(const Types::class_info_t& cls)
		{
			std::uint32_t max_off = 0;
			for (const auto& prop : cls.m_properties)
			{
				if (!prop.m_offset)
					continue;
				// Ignore previously-guessed RTTI pointer fields when sizing the scan window.
				if (prop.m_kind == Types::property_kind_t::pointer && !prop.m_loader_va)
				{
					const auto lower = Common::to_lower(prop.m_sanitized_name);
					if (lower != "properties" && lower != "component_list" && lower != "transform"
						&& lower != "bucket_next" && lower != "next" && lower != "boats_data"
						&& lower != "buckets")
					{
						continue;
					}
				}

				std::uint32_t size = 4;
				switch (prop.m_kind)
				{
				case Types::property_kind_t::vector2: size = 8; break;
				case Types::property_kind_t::vector: size = 16; break;
				case Types::property_kind_t::color: size = 4; break;
				case Types::property_kind_t::rect: size = 16; break;
				case Types::property_kind_t::matrix4: size = 64; break;
				case Types::property_kind_t::int64: size = 8; break;
				case Types::property_kind_t::bool8: size = 1; break;
				default: size = 4; break;
				}
				max_off = (std::max)(max_off, prop.m_offset + size);
			}

			if (is_layout_only_class(cls.m_name))
			{
				// Transform/layout: only scan a little past last trusted field (Scale ~0xBC).
				if (max_off < 0x40)
					max_off = 0xC0;
				return (std::min)(max_off + 0x10, 0x100u);
			}

			// Concrete entities are large; allow a deep window and let consensus filter noise.
			if (Common::ends_with(cls.m_name, "Entity") || Common::ends_with(cls.m_name, "Manager")
				|| Common::ends_with(cls.m_name, "ManagerImpl"))
			{
				return 0x400u;
			}

			if (max_off < 0x80)
				max_off = 0x100;
			return (std::min)(max_off + 0x80, 0x400u);
		}

		[[nodiscard]] static std::string field_name_from_pointee(std::string_view class_name)
		{
			std::string name(class_name);
			if (Common::starts_with(name, "Vu"))
				name = name.substr(2);

			std::string out;
			out.reserve(name.size() + 4);
			for (std::size_t i = 0; i < name.size(); ++i)
			{
				const char c = name[i];
				if (i > 0 && std::isupper(static_cast<unsigned char>(c))
					&& std::islower(static_cast<unsigned char>(name[i - 1])))
				{
					out.push_back('_');
				}
				out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
			}
			if (!out.empty() && std::isdigit(static_cast<unsigned char>(out.front())))
				out.insert(0, "vu_");
			return out;
		}

		// Vote for RTTI pointer slots; commit later only when consensus holds across instances.
		static void collect_typed_pointer_votes(
			HANDLE process,
			std::uint32_t module_base,
			std::uint32_t image_base,
			std::uint32_t owner,
			Types::dump_result_t& result,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class,
			ptr_vote_db_t& votes)
		{
			const auto owner_index = resolve_class_index(process, module_base, image_base, owner, result, vftable_to_class);
			if (owner_index == static_cast<std::size_t>(-1))
				return;

			const auto& owner_cls = result.m_classes[owner_index];
			if (is_layout_only_class(owner_cls.m_name))
				return;

			++votes.m_instances[owner_index];

			const auto scan_end = trusted_scan_end(owner_cls);
			constexpr std::uint32_t k_scan_begin = 0x5C;

			for (std::uint32_t off = k_scan_begin; off + 4 <= scan_end; off += 4)
			{
				// Don't vote on offsets already owned by trusted non-pointer fields.
				bool occupied_scalar = false;
				for (const auto& existing : owner_cls.m_properties)
				{
					if (existing.m_offset != off)
						continue;
					if (existing.m_kind == Types::property_kind_t::pointer
						|| existing.m_kind == Types::property_kind_t::unknown
						|| existing.m_kind == Types::property_kind_t::custom)
					{
						break;
					}
					occupied_scalar = true;
					break;
				}
				if (occupied_scalar)
					continue;

				std::uint32_t ptr = 0;
				if (!read_u32(process, owner + off, ptr) || !ptr)
					continue;
				if (ptr < 0x10000 || (ptr & 3) != 0)
					continue;

				const auto pointee_index = resolve_class_index(process, module_base, image_base, ptr, result, vftable_to_class);
				if (pointee_index == static_cast<std::size_t>(-1))
					continue;

				const auto& pointee_cls = result.m_classes[pointee_index];
				if (!is_interesting_pointee(pointee_cls.m_name))
					continue;
				if (pointee_cls.m_name == owner_cls.m_name)
					continue;

				// Components rarely own arbitrary entity instances; reject entity pointees on components.
				if (Common::ends_with(owner_cls.m_name, "Component")
					&& Common::ends_with(pointee_cls.m_name, "Entity"))
				{
					continue;
				}

				++votes.m_seen[owner_index][off];
				++votes.m_votes[owner_index][off][pointee_cls.m_name];
			}
		}

		[[nodiscard]] static std::size_t commit_typed_pointer_votes(
			Types::dump_result_t& result,
			const ptr_vote_db_t& votes,
			std::ofstream& log)
		{
			std::size_t added = 0;

			for (const auto& [owner_index, by_off] : votes.m_votes)
			{
				if (owner_index >= result.m_classes.size())
					continue;

				auto& owner_cls = result.m_classes[owner_index];
				if (is_layout_only_class(owner_cls.m_name))
					continue;

				const auto instances = votes.m_instances.contains(owner_index)
					? votes.m_instances.at(owner_index)
					: 0u;
				// Boats / rare entities may only have 1 live instance — still allow strong consensus.
				const auto min_instances = Common::ends_with(owner_cls.m_name, "Entity") ? 1u : 2u;
				if (instances < min_instances)
					continue;

				for (const auto& [off, pointee_counts] : by_off)
				{
					const auto seen = votes.m_seen.contains(owner_index) && votes.m_seen.at(owner_index).contains(off)
						? votes.m_seen.at(owner_index).at(off)
						: 0u;
					const auto min_seen = (instances >= 3) ? 2u : 1u;
					if (seen < min_seen)
						continue;

					std::string best_pointee;
					std::uint32_t best_count = 0;
					for (const auto& [pointee, count] : pointee_counts)
					{
						if (count > best_count)
						{
							best_count = count;
							best_pointee = pointee;
						}
					}

					// Require agreement on most observations of this slot.
					if (best_count < min_seen || best_count * 2 < seen)
						continue;
					// And the slot must appear on a meaningful fraction of scanned instances.
					if (instances >= 3 && best_count * 3 < instances && best_count < 3)
						continue;

					bool occupied = false;
					for (auto& existing : owner_cls.m_properties)
					{
						if (existing.m_offset != off)
							continue;

						occupied = true;
						const bool can_upgrade =
							existing.m_kind == Types::property_kind_t::pointer
							|| existing.m_kind == Types::property_kind_t::unknown
							|| existing.m_kind == Types::property_kind_t::custom;
						if (can_upgrade
							&& (existing.m_kind != Types::property_kind_t::pointer
								|| existing.m_pointee_class.empty()))
						{
							existing.m_kind = Types::property_kind_t::pointer;
							existing.m_pointee_class = best_pointee;
							++added;
							log << "ptr-commit " << owner_cls.m_name << " +\"" << existing.m_name
								<< "\" +0x" << std::hex << off << std::dec
								<< " -> " << best_pointee
								<< " votes=" << best_count << "/" << seen
								<< " instances=" << instances << "\n";
						}
						break;
					}
					if (occupied)
						continue;

					const auto base_name = field_name_from_pointee(best_pointee);
					if (base_name.empty())
						continue;

					std::string field_name = base_name;
					bool name_exists = false;
					for (const auto& existing : owner_cls.m_properties)
					{
						if (existing.m_sanitized_name == Common::sanitize_identifier(field_name))
						{
							name_exists = true;
							break;
						}
					}
					if (name_exists)
						field_name = base_name + "_" + std::format("{:x}", off);

					Types::property_info_t prop{};
					prop.m_name = field_name;
					prop.m_sanitized_name = Common::sanitize_identifier(field_name);
					prop.m_offset = off;
					prop.m_kind = Types::property_kind_t::pointer;
					prop.m_pointee_class = best_pointee;
					prop.m_from_engine_model = false;
					owner_cls.m_properties.push_back(std::move(prop));
					++added;

					log << "ptr-commit " << owner_cls.m_name << " +" << field_name
						<< " +0x" << std::hex << off << std::dec
						<< " -> " << best_pointee
						<< " votes=" << best_count << "/" << seen
						<< " instances=" << instances << "\n";
				}

				std::sort(owner_cls.m_properties.begin(), owner_cls.m_properties.end(),
					[](const Types::property_info_t& a, const Types::property_info_t& b)
					{
						if (a.m_offset != b.m_offset)
							return a.m_offset < b.m_offset;
						return a.m_name < b.m_name;
					});
			}

			return added;
		}

		// Remove heap-noise pointer fields accidentally attached to layout-only classes.
		static void strip_spurious_layout_pointers(Types::dump_result_t& result)
		{
			for (auto& cls : result.m_classes)
			{
				if (!is_layout_only_class(cls.m_name))
					continue;

				cls.m_properties.erase(
					std::remove_if(cls.m_properties.begin(), cls.m_properties.end(),
						[](const Types::property_info_t& p)
						{
							if (p.m_kind != Types::property_kind_t::pointer)
								return false;
							if (p.m_loader_va)
								return false;
							const auto lower = Common::to_lower(p.m_sanitized_name);
							return lower != "properties" && lower != "next"
								&& lower != "component_list" && lower != "transform"
								&& lower != "bucket_next";
						}),
					cls.m_properties.end());
			}
		}

		[[nodiscard]] static bool is_fingerprint_noise_name(std::string_view name)
		{
			const auto lower = Common::to_lower(std::string(name));
			static const char* k_noise[] = {
				"vudbasset", "name", "class", "components", "properties", "data",
				"file", "ui", "target", "event", "events", "macros", "stringid",
				"gamedata", "actiongamedata", "locked", "boat", "dockedboat",
				"defaultboatproperties", "assetdb", "news", "tuning",
				"type", "skin", "round", "track", "course", "hud", "audio",
				"online", "credits", "leaderboards", "progress", "championship",
				"slalom", "timetrial", "assets", "langs", "skus", "axes", "buttons",
				"infostringid", "licensemask", "localunlocked", "localvalue",
				"playerboats", "ischampionship", "totaltime", "texture",
			};
			for (const auto* n : k_noise)
			{
				if (lower == n)
					return true;
			}
			return false;
		}

		[[nodiscard]] static bool is_assignment_magnet(std::string_view class_name)
		{
			return class_name == "VuDBAsset"
				|| class_name == "VuEntity"
				|| class_name == "VuComponent"
				|| class_name == "VuProperty";
		}

		static void record_fingerprint(
			live_fingerprint_db_t& db,
			std::size_t class_index,
			const std::string& name,
			std::uint32_t offset)
		{
			db.m_names[class_index].insert(name);
			if (offset)
				db.m_offsets[class_index][name] = offset;
			if (!is_fingerprint_noise_name(name))
				db.m_name_owners[name].insert(class_index);
		}

		static void try_resolve_member_pointee(
			HANDLE process,
			std::uint32_t module_base,
			std::uint32_t image_base,
			std::uint32_t owner,
			std::uint32_t offset,
			Types::property_info_t& prop,
			Types::dump_result_t& result,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class)
		{
			if (!offset || offset >= 0x4000)
				return;

			std::uint32_t ptr = 0;
			if (!read_u32(process, owner + offset, ptr) || !ptr)
				return;
			if (ptr < 0x10000 || (ptr & 3) != 0)
				return;

			const auto pointee_index = resolve_class_index(process, module_base, image_base, ptr, result, vftable_to_class);
			if (pointee_index == static_cast<std::size_t>(-1))
				return;

			const auto& pointee_cls = result.m_classes[pointee_index];
			if (!is_interesting_pointee(pointee_cls.m_name))
				return;

			prop.m_kind = Types::property_kind_t::pointer;
			prop.m_pointee_class = pointee_cls.m_name;
		}

		[[nodiscard]] static std::size_t assign_orphans_by_fingerprint(
			Types::dump_result_t& result,
			live_fingerprint_db_t& db,
			std::ofstream& log)
		{
			// Seed fingerprints from already-bound class members (static + prior live).
			// Live lists alone often miss loader-only / not-currently-spawned types.
			for (std::size_t i = 0; i < result.m_classes.size(); ++i)
			{
				const auto& cls = result.m_classes[i];
				if (Common::starts_with(cls.m_name, "loader_"))
					continue;
				if (!Common::starts_with(cls.m_name, "Vu"))
					continue;

				for (const auto& prop : cls.m_properties)
				{
					if (prop.m_name.empty())
						continue;
					record_fingerprint(db, i, prop.m_name, prop.m_offset);
				}
			}

			if (db.m_names.empty())
				return 0;

			log << "fingerprint_classes=" << db.m_names.size()
				<< " distinctive_names=" << db.m_name_owners.size() << "\n";

			for (auto& orphan : result.m_classes)
			{
				if (!Common::starts_with(orphan.m_name, "loader_") || orphan.m_properties.empty())
					continue;

				std::vector<std::string> distinctive;
				distinctive.reserve(orphan.m_properties.size());
				for (const auto& prop : orphan.m_properties)
				{
					if (!is_fingerprint_noise_name(prop.m_name))
						distinctive.push_back(prop.m_name);
				}

				if (distinctive.empty())
					continue;

				std::size_t best_index = static_cast<std::size_t>(-1);
				std::uint32_t best_overlap = 0;
				std::uint32_t best_unique = 0;

				for (const auto& [class_index, live_names] : db.m_names)
				{
					if (class_index >= result.m_classes.size())
						continue;
					if (Common::starts_with(result.m_classes[class_index].m_name, "loader_"))
						continue;

					std::uint32_t overlap = 0;
					std::uint32_t unique_hits = 0;
					for (const auto& name : distinctive)
					{
						if (!live_names.contains(name))
							continue;
						++overlap;
						if (auto it = db.m_name_owners.find(name);
							it != db.m_name_owners.end() && it->second.size() == 1)
						{
							++unique_hits;
						}
					}

					if (overlap == 0)
						continue;

					const auto& candidate_name = result.m_classes[class_index].m_name;
					const bool magnet = is_assignment_magnet(candidate_name);

					const bool strong =
						(!magnet && overlap == distinctive.size() && overlap >= 2)
						|| (!magnet && unique_hits >= 1 && overlap >= 2 && overlap * 2 >= distinctive.size())
						|| (!magnet && distinctive.size() == 1 && unique_hits == 1)
						|| (!magnet && unique_hits >= 2)
						|| (magnet && overlap >= 3 && unique_hits >= 2 && overlap * 2 >= distinctive.size());

					if (!strong)
						continue;

					if (overlap > best_overlap
						|| (overlap == best_overlap && unique_hits > best_unique))
					{
						best_overlap = overlap;
						best_unique = unique_hits;
						best_index = class_index;
					}
				}

				// Fallback: distinctive names uniquely owned by exactly one non-magnet class.
				if (best_index == static_cast<std::size_t>(-1))
				{
					std::unordered_map<std::size_t, std::uint32_t> votes;
					for (const auto& name : distinctive)
					{
						auto it = db.m_name_owners.find(name);
						if (it == db.m_name_owners.end() || it->second.size() != 1)
							continue;
						const auto idx = *it->second.begin();
						if (idx >= result.m_classes.size())
							continue;
						if (is_assignment_magnet(result.m_classes[idx].m_name))
							continue;
						votes[idx] += 1;
					}

					std::uint32_t best_votes = 0;
					for (const auto& [idx, votes_n] : votes)
					{
						if (votes_n > best_votes)
						{
							best_votes = votes_n;
							best_index = idx;
						}
					}

					// Require the unique owner to explain most of the orphan fingerprint.
					if (best_votes == 0
						|| best_votes * 2 < distinctive.size()
						|| (distinctive.size() >= 3 && best_votes < 2))
					{
						best_index = static_cast<std::size_t>(-1);
					}
					else
					{
						best_overlap = best_votes;
						best_unique = best_votes;
					}
				}

				if (best_index == static_cast<std::size_t>(-1))
					continue;

				merge_orphan_into_class(result, best_index, orphan, db, log, best_overlap, best_unique);
			}

			// Drop emptied orphan loader shells.
			result.m_classes.erase(
				std::remove_if(result.m_classes.begin(), result.m_classes.end(),
					[](const Types::class_info_t& cls)
					{
						return Common::starts_with(cls.m_name, "loader_") && cls.m_properties.empty();
					}),
				result.m_classes.end());

			return db.m_assigned;
		}

		static void strip_engine_model_placeholders(Types::dump_result_t& result)
		{
			for (auto& cls : result.m_classes)
			{
				cls.m_properties.erase(
					std::remove_if(cls.m_properties.begin(), cls.m_properties.end(),
						[](const Types::property_info_t& p)
						{
							return p.m_from_engine_model;
						}),
					cls.m_properties.end());
			}
		}

		[[nodiscard]] static std::size_t rebind_owner_properties(
			HANDLE process,
			std::uint32_t module_base,
			std::uint32_t image_base,
			std::uint32_t owner,
			std::uint32_t prop_list_offset,
			Types::dump_result_t& result,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class,
			live_fingerprint_db_t& fingerprints,
			std::ofstream& log)
		{
			std::uint32_t vftable = 0;
			if (!read_u32(process, owner, vftable) || !vftable)
				return 0;

			std::uint32_t vftable_va = vftable;
			if (vftable >= module_base)
				vftable_va = image_base + (vftable - module_base);

			std::size_t class_index = static_cast<std::size_t>(-1);
			if (auto class_it = vftable_to_class.find(vftable_va); class_it != vftable_to_class.end())
			{
				class_index = class_it->second;
			}
			else
			{
				std::uint32_t col = 0;
				if (vftable >= 4 && read_u32(process, vftable - 4, col) && col)
				{
					std::uint32_t td = 0;
					if (read_u32(process, col + 0x0C, td) && td)
					{
						std::uint32_t td_va = td;
						if (td >= module_base)
							td_va = image_base + (td - module_base);
						for (std::size_t i = 0; i < result.m_classes.size(); ++i)
						{
							if (result.m_classes[i].m_type_descriptor_va == td_va)
							{
								class_index = i;
								break;
							}
						}
					}
				}
			}

			if (class_index == static_cast<std::size_t>(-1))
				return 0;

			auto& cls = result.m_classes[class_index];
			std::uint32_t prop = 0;
			if (!read_u32(process, owner + prop_list_offset, prop))
				return 0;

			std::unordered_set<std::string> live_names;
			std::size_t rebound = 0;
			for (int guard = 0; prop && guard < 256; ++guard)
			{
				std::uint32_t name_ptr = 0;
				std::uint32_t value_ptr = 0;
				std::uint32_t next = 0;
				(void)read_u32(process, prop + 0x04, name_ptr);
				(void)read_u32(process, prop + 0x34, value_ptr);
				(void)read_u32(process, prop + 0x10, next);

				if (name_ptr && value_ptr && value_ptr >= owner)
				{
					const auto offset = value_ptr - owner;
					if (offset < 0x4000)
					{
						const auto name = read_cstring(process, name_ptr, 96);
						if (!name.empty())
						{
							live_names.insert(name);
							record_fingerprint(fingerprints, class_index, name, offset);

							if (merge_live_property(result, cls, name, offset))
							{
								++rebound;
								log << "rebind " << cls.m_name << " +\"" << name
									<< "\" +0x" << std::hex << offset << std::dec << "\n";
							}

							// If this slot holds an object pointer, type it.
							for (auto& p : cls.m_properties)
							{
								if (p.m_name == name || p.m_offset == offset)
								{
									if (p.m_pointee_class.empty())
									{
										try_resolve_member_pointee(
											process, module_base, image_base, owner, offset,
											p, result, vftable_to_class);
									}
									break;
								}
							}
						}
					}
				}

				prop = next;
			}

			if (live_names.size() >= 2)
				assign_orphans_for_live_owner(result, class_index, live_names, fingerprints, log);

			return rebound;
		}

		static void merge_orphan_into_class(
			Types::dump_result_t& result,
			std::size_t class_index,
			Types::class_info_t& orphan,
			live_fingerprint_db_t& db,
			std::ofstream& log,
			std::uint32_t overlap,
			std::uint32_t unique_hits)
		{
			auto& target = result.m_classes[class_index];
			const auto& live_offs = [&]() -> const std::unordered_map<std::string, std::uint32_t>&
			{
				static const std::unordered_map<std::string, std::uint32_t> empty{};
				if (auto it = db.m_offsets.find(class_index); it != db.m_offsets.end())
					return it->second;
				return empty;
			}();

			std::size_t merged = 0;
			for (auto& prop : orphan.m_properties)
			{
				if (auto live_it = live_offs.find(prop.m_name); live_it != live_offs.end() && live_it->second)
					prop.m_offset = live_it->second;

				bool found = false;
				for (auto& existing : target.m_properties)
				{
					if (existing.m_name != prop.m_name
						&& existing.m_sanitized_name != prop.m_sanitized_name)
					{
						continue;
					}

					found = true;
					if (existing.m_offset == 0 && prop.m_offset != 0)
						existing.m_offset = prop.m_offset;
					if (existing.m_kind == Types::property_kind_t::unknown
						&& prop.m_kind != Types::property_kind_t::unknown)
					{
						existing.m_kind = prop.m_kind;
					}
					if (existing.m_pointee_class.empty() && !prop.m_pointee_class.empty())
						existing.m_pointee_class = prop.m_pointee_class;
					if (!existing.m_loader_va && prop.m_loader_va)
						existing.m_loader_va = prop.m_loader_va;
					break;
				}

				if (!found)
				{
					target.m_properties.push_back(prop);
					++merged;
				}
			}

			std::sort(target.m_properties.begin(), target.m_properties.end(),
				[](const Types::property_info_t& a, const Types::property_info_t& b)
				{
					if (a.m_offset != b.m_offset)
						return a.m_offset < b.m_offset;
					return a.m_name < b.m_name;
				});

			log << "orphan-assign " << orphan.m_name << " -> " << target.m_name
				<< " overlap=" << overlap
				<< " unique=" << unique_hits
				<< " merged=" << merged << "\n";

			orphan.m_properties.clear();
			++db.m_assigned;
		}

		static void assign_orphans_for_live_owner(
			Types::dump_result_t& result,
			std::size_t class_index,
			const std::unordered_set<std::string>& live_names,
			live_fingerprint_db_t& db,
			std::ofstream& log)
		{
			if (class_index >= result.m_classes.size() || live_names.size() < 2)
				return;
			if (is_assignment_magnet(result.m_classes[class_index].m_name))
				return;

			for (auto& orphan : result.m_classes)
			{
				if (!Common::starts_with(orphan.m_name, "loader_") || orphan.m_properties.empty())
					continue;

				std::vector<std::string> distinctive;
				for (const auto& prop : orphan.m_properties)
				{
					if (!is_fingerprint_noise_name(prop.m_name))
						distinctive.push_back(prop.m_name);
				}
				if (distinctive.size() < 2)
					continue;

				std::uint32_t overlap = 0;
				for (const auto& name : distinctive)
				{
					if (live_names.contains(name))
						++overlap;
				}

				// Live owner property list must cover most of the orphan fingerprint.
				if (overlap < 2 || overlap * 2 < distinctive.size())
					continue;
				if (overlap != distinctive.size() && overlap < 3)
					continue;

				merge_orphan_into_class(result, class_index, orphan, db, log, overlap, overlap);
			}
		}

		[[nodiscard]] static bool merge_live_property(
			Types::dump_result_t& result,
			Types::class_info_t& cls,
			const std::string& name,
			std::uint32_t offset)
		{
			const auto sanitized = Common::sanitize_identifier(name);
			for (auto& prop : cls.m_properties)
			{
				if (prop.m_name == name || prop.m_sanitized_name == sanitized)
				{
					if (prop.m_offset == 0 && offset != 0)
					{
						prop.m_offset = offset;
						strip_orphan_property(result, name, sanitized);
						return true;
					}
					return false;
				}
				if (prop.m_offset == offset && prop.m_name == name)
					return false;
			}

			Types::property_info_t prop{};
			prop.m_name = name;
			prop.m_sanitized_name = sanitized;
			prop.m_offset = offset;
			prop.m_kind = Types::property_kind_t::custom;
			prop.m_from_engine_model = false;

			const auto lower = Common::to_lower(sanitized);
			if (lower == "position" || lower == "scale" || lower == "rotation"
				|| lower == "relative_position" || lower == "relative_rotation"
				|| lower.find("center") != std::string::npos)
			{
				prop.m_kind = Types::property_kind_t::vector;
			}

			cls.m_properties.push_back(std::move(prop));

			std::sort(cls.m_properties.begin(), cls.m_properties.end(),
				[](const Types::property_info_t& a, const Types::property_info_t& b)
				{
					if (a.m_offset != b.m_offset)
						return a.m_offset < b.m_offset;
					return a.m_name < b.m_name;
				});

			strip_orphan_property(result, name, sanitized);
			return true;
		}

		static void strip_orphan_property(
			Types::dump_result_t& result,
			const std::string& name,
			const std::string& sanitized)
		{
			for (auto& orphan : result.m_classes)
			{
				if (!Common::starts_with(orphan.m_name, "loader_"))
					continue;

				orphan.m_properties.erase(
					std::remove_if(orphan.m_properties.begin(), orphan.m_properties.end(),
						[&](const Types::property_info_t& p)
						{
							return p.m_name == name || p.m_sanitized_name == sanitized;
						}),
					orphan.m_properties.end());
			}
		}

		[[nodiscard]] static DWORD find_process_id(const std::string& name)
		{
			const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			if (snap == INVALID_HANDLE_VALUE)
				return 0;

			PROCESSENTRY32W entry{};
			entry.dwSize = sizeof(entry);
			DWORD pid = 0;

			if (Process32FirstW(snap, &entry))
			{
				do
				{
					char exe[MAX_PATH]{};
					WideCharToMultiByte(CP_UTF8, 0, entry.szExeFile, -1, exe, MAX_PATH, nullptr, nullptr);
					if (_stricmp(exe, name.c_str()) == 0)
					{
						pid = entry.th32ProcessID;
						break;
					}
				} while (Process32NextW(snap, &entry));
			}

			CloseHandle(snap);
			return pid;
		}

		[[nodiscard]] static std::uint32_t find_module_base(HANDLE process, const std::string& module_name)
		{
			HMODULE modules[1024]{};
			DWORD needed = 0;
			if (!EnumProcessModules(process, modules, sizeof(modules), &needed))
				return 0;

			const auto count = needed / sizeof(HMODULE);
			for (DWORD i = 0; i < count; ++i)
			{
				char path[MAX_PATH]{};
				if (!GetModuleBaseNameA(process, modules[i], path, MAX_PATH))
					continue;
				if (_stricmp(path, module_name.c_str()) == 0)
					return static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(modules[i]));
			}
			return 0;
		}

		[[nodiscard]] static bool read_bytes(HANDLE process, std::uint32_t address, void* out, std::size_t size)
		{
			SIZE_T read = 0;
			return ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), out, size, &read)
				&& read == size;
		}

		[[nodiscard]] static bool read_f32(HANDLE process, std::uint32_t address, float& out)
		{
			return read_bytes(process, address, &out, sizeof(out));
		}

		[[nodiscard]] static bool read_vec3(HANDLE process, std::uint32_t address, float out[3])
		{
			float tmp[4]{};
			if (!read_bytes(process, address, tmp, sizeof(tmp)))
				return false;
			out[0] = tmp[0];
			out[1] = tmp[1];
			out[2] = tmp[2];
			return true;
		}

		static void angles_from_basis(const float forward[3], const float up[3], float& yaw, float& pitch, float& roll)
		{
			// VuCamera / FMOD listener basis is Z-up (up ≈ 0,0,1 in-game).
			constexpr float k_rad2deg = 57.2957795f;
			const float fx = forward[0];
			const float fy = forward[1];
			const float fz = forward[2];
			const float horiz = std::sqrt(fx * fx + fy * fy);

			yaw = std::atan2(fy, fx) * k_rad2deg;
			pitch = std::atan2(fz, (std::max)(horiz, 1.0e-8f)) * k_rad2deg;

			const float world_up[3] = { 0.f, 0.f, 1.f };
			const float f_dot_wu = fx * world_up[0] + fy * world_up[1] + fz * world_up[2];
			float proj_up[3] = {
				world_up[0] - fx * f_dot_wu,
				world_up[1] - fy * f_dot_wu,
				world_up[2] - fz * f_dot_wu
			};
			const float plen = std::sqrt(proj_up[0] * proj_up[0] + proj_up[1] * proj_up[1] + proj_up[2] * proj_up[2]);
			if (plen <= 1.0e-6f)
			{
				roll = 0.f;
				return;
			}
			proj_up[0] /= plen;
			proj_up[1] /= plen;
			proj_up[2] /= plen;

			const float cos_r = proj_up[0] * up[0] + proj_up[1] * up[1] + proj_up[2] * up[2];
			const float cross_x = proj_up[1] * up[2] - proj_up[2] * up[1];
			const float cross_y = proj_up[2] * up[0] - proj_up[0] * up[2];
			const float cross_z = proj_up[0] * up[1] - proj_up[1] * up[0];
			const float sin_r = cross_x * fx + cross_y * fy + cross_z * fz;
			roll = std::atan2(sin_r, cos_r) * k_rad2deg;
		}

		static void capture_live_cameras(
			HANDLE process,
			std::uint32_t module_base,
			Types::dump_result_t& result,
			std::ofstream& log)
		{
			result.m_live_cameras.clear();

			// HydroThunder-specific viewport manager / camera layout.
			if (!is_hydro_thunder(result.m_target))
				return;

			constexpr std::uint32_t k_viewport_mgr_rva = 0x359060;
			constexpr std::uint32_t k_count_off = 0x04;
			constexpr std::uint32_t k_camera0_off = 0x28;
			constexpr std::uint32_t k_stride = 0x274;
			constexpr std::uint32_t k_forward_off = 0x140;
			constexpr std::uint32_t k_up_off = 0x150;
			constexpr std::uint32_t k_eye_off = 0x160;

			std::uint32_t manager = 0;
			if (!read_u32(process, module_base + k_viewport_mgr_rva, manager) || !manager)
			{
				log << "\nlive_cameras: viewport manager null\n";
				return;
			}

			std::uint32_t count = 0;
			if (!read_u32(process, manager + k_count_off, count))
			{
				log << "\nlive_cameras: failed to read viewport count\n";
				return;
			}
			if (count == 0 || count > 4)
				count = 1;

			log << "\nlive_cameras:\n";
			log << "  manager=0x" << std::hex << manager << std::dec
				<< " count=" << count << "\n";

			for (std::uint32_t i = 0; i < count; ++i)
			{
				Types::live_camera_t cam{};
				cam.m_viewport_index = i;
				cam.m_viewport_count = count;
				cam.m_manager = manager;
				cam.m_camera = manager + k_camera0_off + i * k_stride;

				if (!read_vec3(process, cam.m_camera + k_eye_off, cam.m_eye)
					|| !read_vec3(process, cam.m_camera + k_forward_off, cam.m_forward)
					|| !read_vec3(process, cam.m_camera + k_up_off, cam.m_up))
				{
					log << "  viewport[" << i << "] read failed\n";
					continue;
				}

				angles_from_basis(cam.m_forward, cam.m_up, cam.m_yaw_deg, cam.m_pitch_deg, cam.m_roll_deg);
				cam.m_valid = true;
				result.m_live_cameras.push_back(cam);

				log << std::fixed << std::setprecision(3);
				log << "  viewport[" << i << "] camera=0x" << std::hex << cam.m_camera << std::dec << "\n";
				log << "    eye=(" << cam.m_eye[0] << ", " << cam.m_eye[1] << ", " << cam.m_eye[2] << ")\n";
				log << "    forward=(" << cam.m_forward[0] << ", " << cam.m_forward[1] << ", " << cam.m_forward[2] << ")\n";
				log << "    up=(" << cam.m_up[0] << ", " << cam.m_up[1] << ", " << cam.m_up[2] << ")\n";
				log << "    yaw_deg=" << cam.m_yaw_deg
					<< " pitch_deg=" << cam.m_pitch_deg
					<< " roll_deg=" << cam.m_roll_deg << "\n";
				log << std::defaultfloat;
			}
		}

		[[nodiscard]] static bool read_u32(HANDLE process, std::uint32_t address, std::uint32_t& out)
		{
			return read_bytes(process, address, &out, sizeof(out));
		}

		[[nodiscard]] static std::string read_cstring(HANDLE process, std::uint32_t address, std::size_t max_len)
		{
			std::string buf(max_len, '\0');
			SIZE_T read = 0;
			if (!ReadProcessMemory(process, reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)), buf.data(), max_len, &read) || !read)
				return {};

			buf.resize(strnlen(buf.c_str(), read));
			for (char c : buf)
			{
				if (c < 0x20 || c > 0x7E)
					return {};
			}
			return buf;
		}
	};
}
