#pragma once

namespace Dumper
{
	class c_property_scanner
	{
	public:
		[[nodiscard]] bool scan(const Pe::c_image& image, Types::dump_result_t& out)
		{
			m_image = &image;

			if (!discover_get_property(out))
			{
				Logger::warn("[c_property_scanner] scan: failed to locate get_property");
				return false;
			}

			Logger::print("[c_property_scanner] scan: get_property=0x%08X", out.m_get_property_va);
			collect_properties(out);

			out.m_property_count = 0;
			for (const auto& c : out.m_classes)
				out.m_property_count += c.m_properties.size();

			Logger::print("[c_property_scanner] scan: extracted %zu properties across %zu classes",
				out.m_property_count, out.m_classes.size());
			return out.m_property_count > 0;
		}

	private:
		const Pe::c_image* m_image = nullptr;

		struct string_ref_t
		{
			std::uint32_t m_string_va = 0;
			std::uint32_t m_insn_rva = 0;
			std::string m_text{};
		};

		[[nodiscard]] static bool looks_like_property_name(std::string_view text)
		{
			if (text.size() < 2 || text.size() > 96)
				return false;
			if (Common::starts_with(text, ".?A"))
				return false;
			if (text.find('%') != std::string_view::npos)
				return false;
			if (text.find("error") != std::string_view::npos)
				return false;
			if (text.find("Error") != std::string_view::npos)
				return false;

			bool has_alpha = false;
			for (char c : text)
			{
				const auto uc = static_cast<unsigned char>(c);
				if (std::isalpha(uc))
					has_alpha = true;
				else if (!(std::isdigit(uc) || c == ' ' || c == '_' || c == '/' || c == '-' || c == '.'))
					return false;
			}
			return has_alpha;
		}

		[[nodiscard]] bool discover_get_property(Types::dump_result_t& out)
		{
			// Pattern from HydroThunder:
			//   push offset "Property Name"
			//   mov ecx, <params>
			//   call get_property
			// get_property prologue:
			//   push ebp
			//   mov ebp, esp
			//   and esp, 0FFFFFFF8h
			//   sub esp, 20h
			//   push esi
			//   mov esi, ecx
			//   push edi
			//   cmp dword ptr [esi], 6

			std::unordered_map<std::uint32_t, std::uint32_t> call_counts;
			const auto size = m_image->size_of_image();

			for (std::uint32_t rva = 0; rva + 10 < size; ++rva)
			{
				if (!m_image->section_is_executable(rva))
					continue;

				const auto* b = m_image->data_rva(rva);
				if (!b)
					continue;

				// push imm32
				if (b[0] != 0x68)
					continue;

				std::uint32_t str_va = 0;
				std::memcpy(&str_va, b + 1, 4);
				if (!m_image->contains_va(str_va))
					continue;

				const auto text = m_image->read_cstring_va(str_va);
				if (!looks_like_property_name(text))
					continue;

				// look ahead for call rel32 within ~16 bytes
				for (std::uint32_t off = 5; off < 24 && rva + off + 5 < size; ++off)
				{
					const auto* p = m_image->data_rva(rva + off);
					if (!p || p[0] != 0xE8)
						continue;

					std::int32_t rel = 0;
					std::memcpy(&rel, p + 1, 4);
					const auto call_site = m_image->rva_to_va(rva + off);
					const auto target = static_cast<std::uint32_t>(call_site + 5 + rel);
					if (!m_image->contains_va(target))
						continue;
					if (!m_image->section_is_executable(m_image->va_to_rva(target)))
						continue;

					++call_counts[target];
					break;
				}
			}

			std::uint32_t best = 0;
			std::uint32_t best_count = 0;
			for (const auto& [va, count] : call_counts)
			{
				if (count < 20)
					continue;
				if (!matches_get_property_prologue(va))
					continue;
				if (count > best_count)
				{
					best = va;
					best_count = count;
				}
			}

			if (!best)
			{
				// fallback: highest count even without prologue match
				for (const auto& [va, count] : call_counts)
				{
					if (count > best_count)
					{
						best = va;
						best_count = count;
					}
				}
			}

			if (!best || best_count < 10)
				return false;

			out.m_get_property_va = best;
			Logger::print("[c_property_scanner] discover: candidate hit_count=%u", best_count);
			return true;
		}

		[[nodiscard]] bool matches_get_property_prologue(std::uint32_t va) const
		{
			const auto rva = m_image->va_to_rva(va);
			const auto* b = m_image->data_rva(rva);
			if (!b)
				return false;

			// push ebp; mov ebp, esp
			if (!(b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC))
				return false;

			// and esp, -8
			if (!(b[3] == 0x83 && b[4] == 0xE4 && b[5] == 0xF8))
				return false;

			return true;
		}

		struct loader_props_t
		{
			std::uint32_t m_loader_va = 0;
			std::uint32_t m_first_call_rva = 0;
			std::vector<Types::property_info_t> m_properties{};
		};

		void collect_properties(Types::dump_result_t& out)
		{
			std::vector<loader_props_t> loaders;
			const auto size = m_image->size_of_image();
			const auto get_prop = out.m_get_property_va;

			for (std::uint32_t rva = 0; rva + 10 < size; ++rva)
			{
				if (!m_image->section_is_executable(rva))
					continue;

				const auto* b = m_image->data_rva(rva);
				if (!b || b[0] != 0x68)
					continue;

				std::uint32_t str_va = 0;
				std::memcpy(&str_va, b + 1, 4);
				if (!m_image->contains_va(str_va))
					continue;

				auto text = m_image->read_cstring_va(str_va);
				if (!looks_like_property_name(text))
					continue;

				std::uint32_t call_rva = 0;
				for (std::uint32_t off = 5; off < 24 && rva + off + 5 < size; ++off)
				{
					const auto* p = m_image->data_rva(rva + off);
					if (!p || p[0] != 0xE8)
						continue;

					std::int32_t rel = 0;
					std::memcpy(&rel, p + 1, 4);
					const auto call_site = m_image->rva_to_va(rva + off);
					const auto target = static_cast<std::uint32_t>(call_site + 5 + rel);
					if (target != get_prop)
						continue;

					call_rva = rva + off;
					break;
				}

				if (!call_rva)
					continue;

				Types::property_info_t prop{};
				prop.m_name = text;
				prop.m_sanitized_name = Common::sanitize_identifier(text);
				prop.m_name_va = str_va;
				prop.m_loader_va = find_function_start(call_rva);

				analyze_property_store(call_rva, prop);
				append_loader_property(loaders, std::move(prop), call_rva);
			}

			bind_loaders_to_classes(out, loaders);
		}

		static void append_loader_property(
			std::vector<loader_props_t>& loaders,
			Types::property_info_t&& prop,
			std::uint32_t call_rva)
		{
			auto it = std::find_if(loaders.begin(), loaders.end(),
				[&](const loader_props_t& l) { return l.m_loader_va == prop.m_loader_va; });

			if (it == loaders.end())
			{
				loader_props_t loader{};
				loader.m_loader_va = prop.m_loader_va;
				loader.m_first_call_rva = call_rva;
				loader.m_properties.push_back(std::move(prop));
				loaders.push_back(std::move(loader));
				return;
			}

			if (call_rva < it->m_first_call_rva)
				it->m_first_call_rva = call_rva;

			for (const auto& existing : it->m_properties)
			{
				if (existing.m_name == prop.m_name && existing.m_offset == prop.m_offset)
					return;
			}
			it->m_properties.push_back(std::move(prop));
		}

		static void sort_properties(std::vector<Types::property_info_t>& props)
		{
			std::sort(props.begin(), props.end(),
				[](const Types::property_info_t& a, const Types::property_info_t& b)
				{
					if (a.m_offset != b.m_offset)
						return a.m_offset < b.m_offset;
					return a.m_name < b.m_name;
				});
		}

		static void merge_properties(Types::class_info_t& cls, std::vector<Types::property_info_t> props)
		{
			for (auto& prop : props)
			{
				bool exists = false;
				for (const auto& existing : cls.m_properties)
				{
					if (existing.m_name == prop.m_name && existing.m_offset == prop.m_offset)
					{
						exists = true;
						break;
					}
				}
				if (!exists)
					cls.m_properties.push_back(std::move(prop));
			}
			sort_properties(cls.m_properties);
		}

		void bind_loaders_to_classes(Types::dump_result_t& out, std::vector<loader_props_t>& loaders)
		{
			std::unordered_map<std::uint32_t, std::size_t> vftable_to_class;
			std::unordered_map<std::uint32_t, std::size_t> method_to_class;
			std::vector<std::pair<std::uint32_t, std::size_t>> method_starts; // sorted for containment
			std::unordered_map<std::string, std::size_t> name_to_class;

			for (std::size_t i = 0; i < out.m_classes.size(); ++i)
			{
				auto& cls = out.m_classes[i];
				name_to_class.emplace(cls.m_name, i);

				if (!cls.m_vftable_va)
					continue;

				vftable_to_class.emplace(cls.m_vftable_va, i);

				const auto vf_rva = m_image->va_to_rva(cls.m_vftable_va);
				std::uint32_t consecutive_bad = 0;
				for (std::uint32_t slot = 0; slot < 256; ++slot)
				{
					const auto fn = m_image->read_rva<std::uint32_t>(vf_rva + slot * 4);
					if (!m_image->contains_va(fn)
						|| !m_image->section_is_executable(m_image->va_to_rva(fn)))
					{
						// MSVC tables can contain non-code holes; don't abort the whole scan.
						++consecutive_bad;
						if (consecutive_bad >= 4)
							break;
						continue;
					}
					consecutive_bad = 0;
					method_to_class.emplace(fn, i);
					method_starts.emplace_back(fn, i);
				}
			}

			std::sort(method_starts.begin(), method_starts.end(),
				[](const auto& a, const auto& b) { return a.first < b.first; });

			Logger::print("[c_property_scanner] bind: vftables=%zu methods=%zu",
				vftable_to_class.size(), method_starts.size());

			std::size_t bound = 0;
			std::size_t unbound = 0;

			for (auto& loader : loaders)
			{
				if (loader.m_properties.empty())
					continue;

				sort_properties(loader.m_properties);

				std::size_t class_index = static_cast<std::size_t>(-1);

				if (auto it = method_to_class.find(loader.m_loader_va); it != method_to_class.end())
					class_index = it->second;

				// Only accept near-exact containment (prologue misdetect by a few bytes).
				if (class_index == static_cast<std::size_t>(-1))
				{
					const auto call_va = m_image->rva_to_va(loader.m_first_call_rva);
					class_index = find_class_by_method_containment(call_va, method_starts, 0x40);
				}

				if (class_index == static_cast<std::size_t>(-1))
					class_index = find_class_from_caller_vftables(loader.m_loader_va, vftable_to_class);

				if (class_index == static_cast<std::size_t>(-1))
					class_index = find_class_from_nearby_type_name(loader.m_loader_va, name_to_class);

				if (class_index == static_cast<std::size_t>(-1))
					class_index = find_class_from_loader_type_string(loader.m_loader_va, name_to_class);

				if (class_index != static_cast<std::size_t>(-1))
				{
					// Drop unresolved offset-0 noise when the loader already has real offsets.
					bool has_resolved = false;
					for (const auto& p : loader.m_properties)
					{
						if (p.m_offset != 0)
						{
							has_resolved = true;
							break;
						}
					}
					if (has_resolved)
					{
						loader.m_properties.erase(
							std::remove_if(loader.m_properties.begin(), loader.m_properties.end(),
								[](const Types::property_info_t& p)
								{
									return p.m_offset == 0
										&& (p.m_kind == Types::property_kind_t::unknown
											|| p.m_kind == Types::property_kind_t::custom);
								}),
							loader.m_properties.end());
					}

					merge_properties(out.m_classes[class_index], std::move(loader.m_properties));
					++bound;
					continue;
				}

				Types::class_info_t synthetic{};
				synthetic.m_name = std::format("loader_{:08X}", loader.m_loader_va);
				synthetic.m_mangled_name = synthetic.m_name;
				synthetic.m_properties = std::move(loader.m_properties);
				out.m_classes.push_back(std::move(synthetic));
				++unbound;
			}

			Logger::print("[c_property_scanner] bind: attached=%zu orphan_loaders=%zu", bound, unbound);

			const auto nested = rebind_orphan_subsystems(out, method_to_class);
			if (nested)
				Logger::print("[c_property_scanner] bind: nested_subsystem_orphans=%zu", nested);
		}

		struct nested_hint_t
		{
			std::size_t m_owner_index = static_cast<std::size_t>(-1);
			std::uint32_t m_member_offset = 0;
			std::string m_section{};
		};

		struct nested_vote_key_t
		{
			std::size_t owner = 0;
			std::uint32_t offset = 0;
			std::string section{};

			bool operator==(const nested_vote_key_t& o) const
			{
				return owner == o.owner && offset == o.offset && section == o.section;
			}
		};

		struct nested_vote_key_hash_t
		{
			std::size_t operator()(const nested_vote_key_t& k) const noexcept
			{
				return std::hash<std::size_t>{}(k.owner)
					^ (std::hash<std::uint32_t>{}(k.offset) << 1)
					^ (std::hash<std::string>{}(k.section) << 2);
			}
		};

		enum class this_source_kind_t : std::uint8_t
		{
			unknown = 0,
			mem_disp,
			reg_this
		};

		struct this_source_t
		{
			this_source_kind_t m_kind = this_source_kind_t::unknown;
			std::uint32_t m_disp = 0;
		};

		[[nodiscard]] static bool is_container_section_name(std::string_view section)
		{
			// get_property keys that name list/map fields, not boat DB sections.
			static constexpr std::string_view k_deny[] = {
				"Properties", "Components", "ChildEntities", "Connections",
				"ChildNodes", "InfoStringID", "Buckets", "Entities", "Assets",
			};
			for (const auto name : k_deny)
			{
				if (section == name)
					return true;
			}
			return false;
		}

		[[nodiscard]] static std::size_t find_class_index_by_name(
			const Types::dump_result_t& out,
			std::string_view name)
		{
			for (std::size_t i = 0; i < out.m_classes.size(); ++i)
			{
				if (out.m_classes[i].m_name == name)
					return i;
			}
			return static_cast<std::size_t>(-1);
		}

		[[nodiscard]] std::size_t rebind_orphan_subsystems(
			Types::dump_result_t& out,
			const std::unordered_map<std::uint32_t, std::size_t>& method_to_class)
		{
			// Orphan loaders that write into nested subsystem objects (no RTTI), e.g.:
			//   mov ecx, [boat+0x22C] ; "Engine"
			//   call apply_engine
			//     call loader_004140C0  ; this == engine
			std::size_t rebound = 0;
			std::vector<std::string> orphan_names;
			for (const auto& cls : out.m_classes)
			{
				if (Common::starts_with(cls.m_name, "loader_") && !cls.m_properties.empty())
					orphan_names.push_back(cls.m_name);
			}

			for (const auto& orphan_name : orphan_names)
			{
				const auto oi = find_class_index_by_name(out, orphan_name);
				if (oi == static_cast<std::size_t>(-1))
					continue;

				auto& orphan = out.m_classes[oi];
				std::uint32_t loader_va = orphan.m_properties.empty() ? 0 : orphan.m_properties.front().m_loader_va;
				if (!loader_va && orphan_name.size() > 7)
					loader_va = static_cast<std::uint32_t>(std::strtoul(orphan_name.c_str() + 7, nullptr, 16));
				if (!loader_va)
					continue;

				const auto hint = discover_nested_subsystem(loader_va, method_to_class);
				if (hint.m_owner_index == static_cast<std::size_t>(-1) || !hint.m_member_offset)
					continue;
				// Require a nearby DB section name ("Engine", "Hull", …) to avoid
				// matching unrelated `mov ecx, [obj+8]` helpers.
				if (hint.m_section.empty())
					continue;
				if (hint.m_owner_index >= out.m_classes.size())
					continue;

				const auto& owner_cls_probe = out.m_classes[hint.m_owner_index];
				// Only attach to real RTTI types (skip templates / synthetic shells).
				if (!owner_cls_probe.m_vftable_va || owner_cls_probe.m_name.find("?$") != std::string::npos)
					continue;
				if (is_container_section_name(hint.m_section))
					continue;

				const auto owner_name = owner_cls_probe.m_name;
				const auto& section = hint.m_section;

				const auto nested_name = owner_name + "_" + Common::sanitize_identifier(section);
				auto nested_index = find_class_index_by_name(out, nested_name);
				if (nested_index == static_cast<std::size_t>(-1))
				{
					Types::class_info_t nested{};
					nested.m_name = nested_name;
					nested.m_mangled_name = nested_name;
					nested.m_is_struct = true;
					out.m_classes.push_back(std::move(nested));
					nested_index = out.m_classes.size() - 1;
				}

				const auto orphan_idx = find_class_index_by_name(out, orphan_name);
				const auto owner_idx = find_class_index_by_name(out, owner_name);
				if (orphan_idx == static_cast<std::size_t>(-1) || owner_idx == static_cast<std::size_t>(-1))
					continue;
				if (out.m_classes[orphan_idx].m_properties.empty())
					continue;

				auto& props = out.m_classes[orphan_idx].m_properties;
				bool has_resolved = false;
				for (const auto& p : props)
				{
					if (p.m_offset != 0)
					{
						has_resolved = true;
						break;
					}
				}
				if (has_resolved)
				{
					// Nested DB keys (Audio/AI/Player/…) resolve at +0 with no real store.
					props.erase(
						std::remove_if(props.begin(), props.end(),
							[](const Types::property_info_t& p) { return p.m_offset == 0; }),
						props.end());
				}

				// These DB section loaders store scalar physics values as floats.
				for (auto& p : props)
				{
					if (p.m_offset == 0)
						continue;
					if (p.m_kind == Types::property_kind_t::int32
						|| p.m_kind == Types::property_kind_t::custom
						|| p.m_kind == Types::property_kind_t::unknown)
					{
						p.m_kind = Types::property_kind_t::float32;
					}
				}

				merge_properties(out.m_classes[nested_index], std::move(props));
				out.m_classes[orphan_idx].m_properties.clear();

				auto& owner_cls = out.m_classes[owner_idx];
				const auto member_name = "m_" + Common::sanitize_identifier(section);
				bool have_ptr = false;
				for (auto& p : owner_cls.m_properties)
				{
					if (p.m_offset != hint.m_member_offset)
						continue;
					have_ptr = true;
					if (p.m_kind == Types::property_kind_t::pointer && p.m_pointee_class.empty())
						p.m_pointee_class = nested_name;
					break;
				}
				if (!have_ptr)
				{
					Types::property_info_t ptr{};
					ptr.m_name = section;
					ptr.m_sanitized_name = Common::sanitize_identifier(section);
					ptr.m_offset = hint.m_member_offset;
					ptr.m_kind = Types::property_kind_t::pointer;
					ptr.m_pointee_class = nested_name;
					ptr.m_loader_va = loader_va;
					owner_cls.m_properties.push_back(std::move(ptr));
					sort_properties(owner_cls.m_properties);
				}

				Types::engine_field_t field{};
				field.m_owner = owner_cls.m_name;
				field.m_name = member_name;
				field.m_offset = hint.m_member_offset;
				field.m_kind = Types::property_kind_t::pointer;
				field.m_pointee_class = nested_name;
				field.m_note = std::format("nested subsystem \"{}\" via loader 0x{:08X}", section, loader_va);
				out.m_engine_fields.push_back(std::move(field));

				Logger::print("[c_property_scanner] nested: %s -> %s::%s+0x%X (%s*)",
					orphan_name.c_str(), owner_cls.m_name.c_str(), member_name.c_str(),
					hint.m_member_offset, nested_name.c_str());
				++rebound;
			}

			out.m_classes.erase(
				std::remove_if(out.m_classes.begin(), out.m_classes.end(),
					[](const Types::class_info_t& c)
					{
						return Common::starts_with(c.m_name, "loader_") && c.m_properties.empty();
					}),
				out.m_classes.end());

			return rebound;
		}

		[[nodiscard]] nested_hint_t discover_nested_subsystem(
			std::uint32_t loader_va,
			const std::unordered_map<std::uint32_t, std::size_t>& method_to_class) const
		{
			nested_hint_t best{};
			std::uint32_t best_votes = 0;
			std::unordered_map<nested_vote_key_t, std::uint32_t, nested_vote_key_hash_t> votes;

			for (const auto site_rva : find_call_sites(loader_va))
				collect_nested_votes_from_call(site_rva, loader_va, 0, method_to_class, votes);

			for (const auto& [key, count] : votes)
			{
				if (count > best_votes)
				{
					best_votes = count;
					best.m_owner_index = key.owner;
					best.m_member_offset = key.offset;
					best.m_section = key.section;
				}
			}

			return best_votes > 0 ? best : nested_hint_t{};
		}

		void collect_nested_votes_from_call(
			std::uint32_t call_rva,
			std::uint32_t callee_va,
			int depth,
			const std::unordered_map<std::uint32_t, std::size_t>& method_to_class,
			std::unordered_map<nested_vote_key_t, std::uint32_t, nested_vote_key_hash_t>& votes) const
		{
			if (depth > 3 || !call_rva)
				return;

			const auto this_src = decode_thiscall_this_source(call_rva);
			if (this_src.m_kind == this_source_kind_t::mem_disp)
			{
				const auto owner_fn = find_function_start(call_rva);
				const auto owner_idx = resolve_class_for_function(owner_fn, method_to_class);
				if (owner_idx == static_cast<std::size_t>(-1))
					return;

				nested_vote_key_t key{};
				key.owner = owner_idx;
				key.offset = this_src.m_disp;
				key.section = find_nearby_section_name(call_rva);
				++votes[key];
				return;
			}

			// Loader applied to the caller's `this` — walk one level up.
			const auto wrapper_va = find_function_start(call_rva);
			if (!wrapper_va || wrapper_va == callee_va)
				return;

			for (const auto parent_rva : find_call_sites(wrapper_va))
			{
				collect_nested_votes_from_call(
					parent_rva, wrapper_va, depth + 1, method_to_class, votes);
			}
		}

		[[nodiscard]] std::vector<std::uint32_t> find_call_sites(std::uint32_t target_va) const
		{
			std::vector<std::uint32_t> sites;
			if (!target_va || !m_image)
				return sites;

			const auto size = m_image->size_of_image();
			for (std::uint32_t rva = 0; rva + 5 < size; ++rva)
			{
				if (!m_image->section_is_executable(rva))
					continue;

				const auto* b = m_image->data_rva(rva);
				if (!b || b[0] != 0xE8)
					continue;

				std::int32_t rel = 0;
				std::memcpy(&rel, b + 1, 4);
				const auto call_site = m_image->rva_to_va(rva);
				const auto target = static_cast<std::uint32_t>(call_site + 5 + rel);
				if (target == target_va)
					sites.push_back(rva);
			}
			return sites;
		}

		[[nodiscard]] this_source_t decode_thiscall_this_source(std::uint32_t call_rva) const
		{
			// Scan backwards for ECX setup immediately before `call`.
			this_source_t result{};
			if (!call_rva || call_rva < 0x10)
				return result;

			const auto size = m_image->size_of_image();
			const std::uint32_t window = call_rva > 0x40 ? 0x40 : call_rva;
			int tracked_reg = -1; // after `mov ecx, r32`, follow that register

			for (std::uint32_t back = 2; back <= window; ++back)
			{
				const auto rva = call_rva - back;
				const auto* b = m_image->data_rva(rva);
				if (!b || rva + 8 >= size)
					continue;

				// mov r32, [reg+disp]  8B /r
				if (b[0] == 0x8B)
				{
					const auto mod = (b[1] >> 6) & 3;
					const auto reg = (b[1] >> 3) & 7;
					const auto rm = b[1] & 7;
					if (rm == 4)
						continue; // SIB
					if (rm == 5 && mod != 0)
						continue; // [ebp+disp] stack frame — not an object field

					std::uint32_t disp = 0;
					bool is_mem = false;
					if (mod == 1)
					{
						disp = static_cast<std::uint8_t>(b[2]);
						is_mem = true;
					}
					else if (mod == 2)
					{
						std::memcpy(&disp, b + 2, 4);
						is_mem = true;
					}
					else if (mod == 0 && rm != 5)
					{
						disp = 0;
						is_mem = true;
					}

					if (is_mem && reg == 1) // mov ecx, [..]
					{
						if (disp != 0)
						{
							result.m_kind = this_source_kind_t::mem_disp;
							result.m_disp = disp;
							return result;
						}
					}

					if (is_mem && tracked_reg >= 0 && reg == tracked_reg && disp != 0)
					{
						result.m_kind = this_source_kind_t::mem_disp;
						result.m_disp = disp;
						return result;
					}

					// mov ecx, r32
					if (mod == 3 && reg == 1)
					{
						tracked_reg = rm;
						result.m_kind = this_source_kind_t::reg_this;
						continue;
					}

					// mov tracked, other_reg — keep following
					if (mod == 3 && tracked_reg >= 0 && reg == tracked_reg)
						tracked_reg = rm;
				}
			}

			return result;
		}

		[[nodiscard]] std::size_t resolve_class_for_function(
			std::uint32_t fn_va,
			const std::unordered_map<std::uint32_t, std::size_t>& method_to_class) const
		{
			if (!fn_va)
				return static_cast<std::size_t>(-1);

			if (auto it = method_to_class.find(fn_va); it != method_to_class.end())
				return it->second;

			// Helper called from a vftable method (e.g. boat setup from VuBoatEntity::fn).
			std::unordered_map<std::size_t, std::uint32_t> votes;
			for (const auto site_rva : find_call_sites(fn_va))
			{
				const auto caller = find_function_start(site_rva);
				if (auto it = method_to_class.find(caller); it != method_to_class.end())
					++votes[it->second];
			}

			std::size_t best = static_cast<std::size_t>(-1);
			std::uint32_t best_votes = 0;
			for (const auto& [idx, count] : votes)
			{
				if (count > best_votes)
				{
					best = idx;
					best_votes = count;
				}
			}
			return best_votes > 0 ? best : static_cast<std::size_t>(-1);
		}

		[[nodiscard]] std::string find_nearby_section_name(std::uint32_t call_rva) const
		{
			// Prefer push "Engine"/"Hull"/… immediately before the thiscall.
			if (!call_rva)
				return {};

			const auto size = m_image->size_of_image();
			const std::uint32_t begin = call_rva > 0x80 ? call_rva - 0x80 : 0;
			std::string best;

			for (std::uint32_t rva = begin; rva + 5 < call_rva && rva + 5 < size; ++rva)
			{
				const auto* b = m_image->data_rva(rva);
				if (!b || b[0] != 0x68)
					continue;

				std::uint32_t str_va = 0;
				std::memcpy(&str_va, b + 1, 4);
				if (!m_image->contains_va(str_va))
					continue;

				auto text = m_image->read_cstring_va(str_va, 48);
				if (text.size() < 2 || text.size() > 24)
					continue;
				if (text.find(' ') != std::string::npos)
					continue;
				if (!std::isalpha(static_cast<unsigned char>(text.front())))
					continue;

				bool ok = true;
				for (char c : text)
				{
					if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_')
					{
						ok = false;
						break;
					}
				}
				if (!ok)
					continue;

				// Skip common non-section names.
				if (text == "Default" || text == "VuDBAsset" || Common::starts_with(text, "Vu"))
					continue;

				best = std::move(text); // nearest wins (scan forward)
			}

			return best;
		}

		[[nodiscard]] static std::size_t find_class_by_method_containment(
			std::uint32_t call_va,
			const std::vector<std::pair<std::uint32_t, std::size_t>>& method_starts,
			std::uint32_t max_distance)
		{
			if (method_starts.empty() || !call_va)
				return static_cast<std::size_t>(-1);

			std::size_t best = static_cast<std::size_t>(-1);
			std::uint32_t best_start = 0;
			for (const auto& [fn, idx] : method_starts)
			{
				if (fn > call_va)
					break;
				if (call_va - fn > max_distance)
					continue;
				if (fn >= best_start)
				{
					best_start = fn;
					best = idx;
				}
			}
			return best;
		}

		[[nodiscard]] std::size_t find_class_from_caller_vftables(
			std::uint32_t loader_va,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class) const
		{
			const auto size = m_image->size_of_image();
			std::unordered_map<std::size_t, std::uint32_t> votes;

			for (std::uint32_t rva = 0; rva + 5 < size; ++rva)
			{
				if (!m_image->section_is_executable(rva))
					continue;

				const auto* b = m_image->data_rva(rva);
				if (!b || b[0] != 0xE8)
					continue;

				std::int32_t rel = 0;
				std::memcpy(&rel, b + 1, 4);
				const auto call_site = m_image->rva_to_va(rva);
				const auto target = static_cast<std::uint32_t>(call_site + 5 + rel);
				if (target != loader_va)
					continue;

				const auto caller_va = find_function_start(rva);
				const auto caller_rva = m_image->va_to_rva(caller_va);

				// Scan caller body for vftable assignments.
				for (std::uint32_t off = 0; off < 0x1000 && caller_rva + off + 6 < size; ++off)
				{
					const auto* p = m_image->data_rva(caller_rva + off);
					if (!p)
						break;

					// mov dword ptr [reg(+disp)], imm32
					if (p[0] == 0xC7 && (p[1] & 0x38) == 0x00)
					{
						const auto mod = (p[1] >> 6) & 3;
						const auto rm = p[1] & 7;
						std::uint32_t imm_at = 0;
						if (mod == 0 && rm != 4 && rm != 5)
							imm_at = 2;
						else if (mod == 1 && rm != 4)
							imm_at = 3;
						else if (mod == 2 && rm != 4)
							imm_at = 6;
						else
							continue;

						if (caller_rva + off + imm_at + 4 >= size)
							continue;

						std::uint32_t imm = 0;
						std::memcpy(&imm, p + imm_at, 4);
						if (auto it = vftable_to_class.find(imm); it != vftable_to_class.end())
							++votes[it->second];
					}

					// mov reg, imm32 (B8+r) where imm is a vftable
					if ((p[0] & 0xF8) == 0xB8)
					{
						std::uint32_t imm = 0;
						std::memcpy(&imm, p + 1, 4);
						if (auto it = vftable_to_class.find(imm); it != vftable_to_class.end())
							++votes[it->second];
					}

					if (p[0] == 0xC3 || p[0] == 0xC2)
						break;
				}
			}

			std::size_t best = static_cast<std::size_t>(-1);
			std::uint32_t best_votes = 0;
			for (const auto& [idx, count] : votes)
			{
				if (count > best_votes)
				{
					best = idx;
					best_votes = count;
				}
			}
			return best_votes > 0 ? best : static_cast<std::size_t>(-1);
		}

		[[nodiscard]] std::size_t find_class_from_nearby_type_name(
			std::uint32_t loader_va,
			const std::unordered_map<std::string, std::size_t>& name_to_class) const
		{
			// Some registration tables store (name, fn). Search for absolute pointer to loader
			// followed/preceded by a class name string pointer.
			const auto size = m_image->size_of_image();
			for (std::uint32_t rva = 0; rva + 8 < size; rva += 4)
			{
				if (m_image->section_is_executable(rva))
					continue;

				const auto value = m_image->read_rva<std::uint32_t>(rva);
				if (value != loader_va)
					continue;

				for (const auto delta : { -4, 4, -8, 8 })
				{
					const auto probe = static_cast<std::int64_t>(rva) + delta;
					if (probe < 0 || static_cast<std::uint32_t>(probe) + 4 >= size)
						continue;

					const auto maybe_str = m_image->read_rva<std::uint32_t>(static_cast<std::uint32_t>(probe));
					if (!m_image->contains_va(maybe_str))
						continue;

					const auto text = m_image->read_cstring_va(maybe_str, 128);
					if (text.empty())
						continue;

					if (auto it = name_to_class.find(text); it != name_to_class.end())
						return it->second;
				}
			}

			return static_cast<std::size_t>(-1);
		}

		[[nodiscard]] std::size_t find_class_from_loader_type_string(
			std::uint32_t loader_va,
			const std::unordered_map<std::string, std::size_t>& name_to_class) const
		{
			// Loaders / converters often push the Vu* type name they operate on
			// (e.g. sub_4BC790 compares against "VuTransformComponent").
			if (!loader_va || !m_image->contains_va(loader_va))
				return static_cast<std::size_t>(-1);

			const auto start_rva = m_image->va_to_rva(loader_va);
			const auto size = m_image->size_of_image();
			std::unordered_map<std::size_t, std::uint32_t> votes;

			for (std::uint32_t off = 0; off < 0x800 && start_rva + off + 5 < size; ++off)
			{
				const auto* b = m_image->data_rva(start_rva + off);
				if (!b)
					break;

				if (b[0] == 0xC3 || b[0] == 0xC2)
					break;

				if (b[0] != 0x68)
					continue;

				std::uint32_t str_va = 0;
				std::memcpy(&str_va, b + 1, 4);
				if (!m_image->contains_va(str_va))
					continue;

				const auto text = m_image->read_cstring_va(str_va, 96);
				if (text.size() < 3 || !Common::starts_with(text, "Vu"))
					continue;
				if (text.find(' ') != std::string::npos)
					continue;

				if (auto it = name_to_class.find(text); it != name_to_class.end())
					++votes[it->second];
			}

			std::size_t best = static_cast<std::size_t>(-1);
			std::uint32_t best_votes = 0;
			for (const auto& [idx, count] : votes)
			{
				if (count > best_votes)
				{
					best = idx;
					best_votes = count;
				}
			}
			return best_votes > 0 ? best : static_cast<std::size_t>(-1);
		}

		[[nodiscard]] std::uint32_t find_function_start(std::uint32_t insn_rva) const
		{
			// Walk backwards for common MSVC prologues / alignment padding.
			// Large methods (e.g. VuBoatEntity setup ~0xA17) need a wide window.
			std::uint32_t best = insn_rva;
			for (std::uint32_t i = 0; i < 0x1200; ++i)
			{
				if (insn_rva < i)
					break;

				const auto rva = insn_rva - i;
				const auto* b = m_image->data_rva(rva);
				if (!b)
					continue;

				const bool aligned = (rva & 0xF) == 0;
				const bool prologue =
					(b[0] == 0x55 && b[1] == 0x8B && b[2] == 0xEC) || // push ebp; mov ebp, esp
					(b[0] == 0x53 && b[1] == 0x56 && b[2] == 0x57) || // push ebx/esi/edi
					(b[0] == 0x56 && b[1] == 0x57);                   // push esi/edi

				if (prologue && (aligned || i < 8))
				{
					best = rva;
					if (aligned)
						break;
				}

				// int3 / nop padding often precedes functions
				if (i > 0 && (b[0] == 0xCC || b[0] == 0x90) && prologue == false)
					continue;
			}

			return m_image->rva_to_va(best);
		}

		void analyze_property_store(std::uint32_t call_rva, Types::property_info_t& prop) const
		{
			// After call:
			//   mov ecx, [eax]
			//   cmp ecx, 1 / 2 / 7 / 4
			//   ...
			//   movss dword ptr [edi+disp], xmm0
			//   mov [edi+disp], eax
			prop.m_kind = Types::property_kind_t::unknown;
			prop.m_offset = 0;
			prop.m_type_tag = 0;

			const auto size = m_image->size_of_image();
			std::uint32_t seen_tag = 0;
			std::uint32_t seen_offset = 0;
			bool found_offset = false;

			for (std::uint32_t off = 5; off < 0x80 && call_rva + off + 8 < size; ++off)
			{
				const auto* b = m_image->data_rva(call_rva + off);
				if (!b)
					break;

				// stop at next push offset string / call get_property region boundary-ish
				if (b[0] == 0x68 && off > 16)
				{
					std::uint32_t maybe = 0;
					std::memcpy(&maybe, b + 1, 4);
					if (m_image->contains_va(maybe))
					{
						const auto text = m_image->read_cstring_va(maybe);
						if (looks_like_property_name(text))
							break;
					}
				}

				// cmp ecx/reg, imm8  => tag
				if (b[0] == 0x83 && (b[1] == 0xF9 || b[1] == 0xF8 || b[1] == 0xFA || b[1] == 0xFB))
				{
					seen_tag = b[2];
					if (prop.m_type_tag == 0)
						prop.m_type_tag = seen_tag;
				}

				// mov [reg+disp8], ...
				if (b[0] == 0x89 && (b[1] & 0xC0) != 0xC0)
				{
					const auto mod = (b[1] >> 6) & 3;
					const auto rm = b[1] & 7;
					if (mod == 1 && rm != 4) // [reg+disp8]
					{
						seen_offset = static_cast<std::uint8_t>(b[2]);
						found_offset = true;
					}
					else if (mod == 2 && rm != 4) // [reg+disp32]
					{
						std::memcpy(&seen_offset, b + 2, 4);
						found_offset = true;
					}
				}

				// movss dword ptr [reg+disp], xmm*  => scalar float field
				// F3 0F 11 /r
				if (b[0] == 0xF3 && b[1] == 0x0F && b[2] == 0x11)
				{
					const auto modrm = b[3];
					const auto mod = (modrm >> 6) & 3;
					const auto rm = modrm & 7;
					if (mod == 1 && rm != 4)
					{
						seen_offset = static_cast<std::uint8_t>(b[4]);
						found_offset = true;
						prop.m_kind = Types::property_kind_t::float32;
					}
					else if (mod == 2 && rm != 4)
					{
						std::memcpy(&seen_offset, b + 4, 4);
						found_offset = true;
						prop.m_kind = Types::property_kind_t::float32;
					}
				}

				// fstp dword ptr [reg+disp]  => D9 5r / D9 9r
				if (b[0] == 0xD9 && ((b[1] & 0xF8) == 0x58 || (b[1] & 0xF8) == 0x98))
				{
					const auto mod = (b[1] >> 6) & 3;
					if (mod == 1)
					{
						seen_offset = static_cast<std::uint8_t>(b[2]);
						found_offset = true;
						prop.m_kind = Types::property_kind_t::float32;
					}
				}

				if (found_offset && (prop.m_type_tag != 0 || prop.m_kind != Types::property_kind_t::unknown))
					break;
			}

			if (found_offset)
				prop.m_offset = seen_offset;

			if (prop.m_kind == Types::property_kind_t::unknown)
				prop.m_kind = Types::property_kind_from_tag(prop.m_type_tag);
			if (prop.m_kind == Types::property_kind_t::unknown && found_offset)
				prop.m_kind = Types::property_kind_t::custom;
		}
	};
}
