#pragma once

namespace Dumper
{
	// Builds emitted engine fields / pointer chains from discovered globals +
	// class properties, plus structural layouts recovered from ctors / memcpy
	// sites for system components that have no VuProperty reflection
	// (e.g. VuViewportManager / embedded VuCamera).
	class c_engine_model
	{
	public:
		static void apply(Types::dump_result_t& out)
		{
			// Drop prior structural seeds so re-runs stay idempotent.
			for (auto& cls : out.m_classes)
			{
				cls.m_properties.erase(
					std::remove_if(cls.m_properties.begin(), cls.m_properties.end(),
						[](const Types::property_info_t& p)
						{
							return p.m_from_engine_model;
						}),
					cls.m_properties.end());
			}

			label_discovered_globals(out);
			rebuild_from_discovered(out);
		}

		static void rebuild_from_discovered(Types::dump_result_t& out)
		{
			out.m_engine_fields.clear();
			out.m_chains.clear();

			seed_structural_layouts(out);
			collect_fields_from_classes(out);
			build_dynamic_chains(out);

			Logger::print("[c_engine_model] rebuild: fields=%zu globals=%zu chains=%zu",
				out.m_engine_fields.size(), out.m_globals.size(), out.m_chains.size());
		}

	private:
		// VuViewportManager ctor (sub_530B00 / new 0x9D8) + consumers
		// (memcpy size 0x240 to manager+0x28, stride 0x274 / 628).
		static constexpr std::uint32_t k_viewport_manager_size = 0x9D8;
		static constexpr std::uint32_t k_viewport_count_off = 0x04;
		static constexpr std::uint32_t k_viewport0_off = 0x08;
		static constexpr std::uint32_t k_camera0_off = 0x28;       // getCamera(0)
		static constexpr std::uint32_t k_viewport_stride = 0x274;  // 628
		static constexpr std::uint32_t k_camera_size = 0x240;
		static constexpr std::uint32_t k_camera_in_viewport = 0x20; // relative to viewport base

		// VuCamera (sub_50BA20) — offsets relative to camera base.
		static constexpr std::uint32_t k_cam_velocity = 0x20;
		static constexpr std::uint32_t k_cam_proj = 0x30;
		static constexpr std::uint32_t k_cam_view = 0xF0;
		static constexpr std::uint32_t k_cam_forward = 0x140;
		static constexpr std::uint32_t k_cam_up = 0x150;
		static constexpr std::uint32_t k_cam_eye = 0x160;

		[[nodiscard]] static const Types::class_info_t* find_class(
			const Types::dump_result_t& out,
			std::string_view name)
		{
			for (const auto& cls : out.m_classes)
			{
				if (cls.m_name == name)
					return &cls;
			}
			return nullptr;
		}

		[[nodiscard]] static Types::class_info_t* find_class_mut(
			Types::dump_result_t& out,
			std::string_view name)
		{
			for (auto& cls : out.m_classes)
			{
				if (cls.m_name == name)
					return &cls;
			}
			return nullptr;
		}

		[[nodiscard]] static const Types::property_info_t* find_property(
			const Types::class_info_t& cls,
			std::string_view name)
		{
			const auto want = Common::sanitize_identifier(std::string(name));
			for (const auto& prop : cls.m_properties)
			{
				if (prop.m_offset == 0)
					continue;
				if (prop.m_name == name
					|| prop.m_sanitized_name == want
					|| Common::to_lower(prop.m_sanitized_name) == Common::to_lower(want))
				{
					return &prop;
				}
			}
			return nullptr;
		}

		[[nodiscard]] static const Types::global_info_t* find_global_by_class(
			const Types::dump_result_t& out,
			std::string_view class_name)
		{
			for (const auto& g : out.m_globals)
			{
				if (g.m_class_name == class_name && g.m_rva)
					return &g;
			}
			return nullptr;
		}

		[[nodiscard]] static const Types::global_info_t* find_global_by_rva(
			const Types::dump_result_t& out,
			std::uint32_t rva)
		{
			for (const auto& g : out.m_globals)
			{
				if (g.m_rva == rva)
					return &g;
			}
			return nullptr;
		}

		static void label_discovered_globals(Types::dump_result_t& out)
		{
			// Class-name labeling works for any VuEngine title.
			for (auto& g : out.m_globals)
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
				else if (g.m_class_name == "VuViewportManager")
					g.m_name = "g_vu_viewport_manager";
			}

			// HydroThunder-only: known singleton RVAs when static scan lacked a vftable class.
			if (is_hydro_thunder(out.m_target))
			{
				struct known_slot_t
				{
					std::uint32_t rva;
					const char* name;
					const char* class_name;
				};
				static constexpr known_slot_t k_known[] = {
					{ 0x358FB8, "g_vu_boat_manager", "VuBoatManager" },
					{ 0x358FDC, "g_vu_project_manager", "VuProjectManager" },
					{ 0x358FF0, "g_vu_game_mode_manager", "VuGameModeManagerImpl" },
					{ 0x359014, "g_vu_dev_menu", "VuDevMenu" },
					{ 0x359060, "g_vu_viewport_manager", "VuViewportManager" },
					{ 0x359080, "g_vu_entity_repository", "VuEntityRepositoryImpl" },
				};

				for (auto& g : out.m_globals)
				{
					for (const auto& known : k_known)
					{
						if (g.m_rva != known.rva)
							continue;
						g.m_name = known.name;
						if (g.m_class_name.empty())
							g.m_class_name = known.class_name;
						break;
					}
				}
			}
		}

		static Types::class_info_t& ensure_class(
			Types::dump_result_t& out,
			std::string_view name,
			bool is_struct = false)
		{
			if (auto* existing = find_class_mut(out, name))
			{
				if (is_struct)
					existing->m_is_struct = true;
				return *existing;
			}

			Types::class_info_t cls{};
			cls.m_name = std::string(name);
			cls.m_mangled_name = std::format(".?AV{}@@", name);
			cls.m_is_struct = is_struct;
			out.m_classes.push_back(std::move(cls));
			return out.m_classes.back();
		}

		static void add_structural_prop(
			Types::class_info_t& cls,
			std::string name,
			std::uint32_t offset,
			Types::property_kind_t kind,
			std::string pointee = {})
		{
			for (const auto& existing : cls.m_properties)
			{
				if (existing.m_offset == offset
					&& (existing.m_name == name
						|| existing.m_sanitized_name == Common::sanitize_identifier(name)))
				{
					return;
				}
			}

			Types::property_info_t prop{};
			prop.m_name = std::move(name);
			prop.m_sanitized_name = Common::sanitize_identifier(prop.m_name);
			prop.m_offset = offset;
			prop.m_kind = kind;
			prop.m_from_engine_model = true;
			prop.m_pointee_class = std::move(pointee);
			cls.m_properties.push_back(std::move(prop));
		}

		static void seed_structural_layouts(Types::dump_result_t& out)
		{
			// Viewport/camera layouts below were recovered from HydroThunder.exe.
			if (!is_hydro_thunder(out.m_target))
				return;

			// Plain aggregate — no RTTI type descriptor in this binary.
			auto& camera = ensure_class(out, "VuCamera", true);
			add_structural_prop(camera, "Velocity", k_cam_velocity, Types::property_kind_t::vector);
			add_structural_prop(camera, "ProjMatrix", k_cam_proj, Types::property_kind_t::matrix4);
			add_structural_prop(camera, "ViewMatrix", k_cam_view, Types::property_kind_t::matrix4);
			add_structural_prop(camera, "Forward", k_cam_forward, Types::property_kind_t::vector);
			add_structural_prop(camera, "Up", k_cam_up, Types::property_kind_t::vector);
			add_structural_prop(camera, "EyePosition", k_cam_eye, Types::property_kind_t::vector);

			// Embedded cameras: getCamera(i) = this + 0x28 + i*0x274 (size 0x240).
			// Viewport slots begin at +0x08; camera is +0x20 into each 0x274 slot.
			auto& vpm = ensure_class(out, "VuViewportManager", false);
			add_structural_prop(vpm, "ViewportCount", k_viewport_count_off, Types::property_kind_t::int32);
			add_structural_prop(vpm, "Camera", k_camera0_off, Types::property_kind_t::custom);
			add_structural_prop(vpm, "Camera0_ProjMatrix",
				k_camera0_off + k_cam_proj, Types::property_kind_t::matrix4);
			add_structural_prop(vpm, "Camera0_ViewMatrix",
				k_camera0_off + k_cam_view, Types::property_kind_t::matrix4);
			add_structural_prop(vpm, "Camera0_Forward",
				k_camera0_off + k_cam_forward, Types::property_kind_t::vector);
			add_structural_prop(vpm, "Camera0_Up",
				k_camera0_off + k_cam_up, Types::property_kind_t::vector);
			add_structural_prop(vpm, "Camera0_EyePosition",
				k_camera0_off + k_cam_eye, Types::property_kind_t::vector);
			add_structural_prop(vpm, "Camera1",
				k_camera0_off + k_viewport_stride, Types::property_kind_t::custom);
			add_structural_prop(vpm, "Camera2",
				k_camera0_off + 2 * k_viewport_stride, Types::property_kind_t::custom);
			add_structural_prop(vpm, "Camera3",
				k_camera0_off + 3 * k_viewport_stride, Types::property_kind_t::custom);

			(void)k_viewport_manager_size;
			(void)k_camera_size;
			(void)k_camera_in_viewport;
			(void)k_viewport0_off;
		}

		static void collect_fields_from_classes(Types::dump_result_t& out)
		{
			for (const auto& cls : out.m_classes)
			{
				if (Common::starts_with(cls.m_name, "loader_"))
					continue;
				if (!Common::starts_with(cls.m_name, "Vu"))
					continue;

				for (const auto& prop : cls.m_properties)
				{
					Types::engine_field_t field{};
					field.m_owner = cls.m_name;
					field.m_name = prop.m_name;
					field.m_offset = prop.m_offset;
					field.m_kind = prop.m_kind;
					field.m_pointee_class = prop.m_pointee_class;
					if (prop.m_from_engine_model)
					{
						if (cls.m_name == "VuViewportManager" && prop.m_name == "Camera")
							field.m_note = "ida/structural getCamera(0); size=0x240; stride=0x274";
						else if (cls.m_name == "VuViewportManager"
							&& (prop.m_name == "Camera1" || prop.m_name == "Camera2" || prop.m_name == "Camera3"))
							field.m_note = "ida/structural getCamera(i); size=0x240";
						else
							field.m_note = "ida/structural";
					}
					else if (prop.m_loader_va)
						field.m_note = std::format("loader=0x{:X}", prop.m_loader_va);
					else
						field.m_note = "live/dynamic";
					out.m_engine_fields.push_back(std::move(field));
				}
			}

			std::sort(out.m_engine_fields.begin(), out.m_engine_fields.end(),
				[](const Types::engine_field_t& a, const Types::engine_field_t& b)
				{
					if (a.m_owner != b.m_owner)
						return a.m_owner < b.m_owner;
					if (a.m_offset != b.m_offset)
						return a.m_offset < b.m_offset;
					return a.m_name < b.m_name;
				});
		}

		static void add_step(
			Types::pointer_chain_t& chain,
			std::string label,
			std::string from,
			std::string how,
			std::uint32_t offset_or_rva,
			bool is_global_rva = false)
		{
			Types::pointer_chain_step_t step{};
			step.m_label = std::move(label);
			step.m_from = std::move(from);
			step.m_how = std::move(how);
			step.m_offset_or_rva = offset_or_rva;
			step.m_is_global_rva = is_global_rva;
			chain.m_steps.push_back(std::move(step));
		}

		static void build_dynamic_chains(Types::dump_result_t& out)
		{
			const auto* repo = find_global_by_class(out, "VuEntityRepositoryImpl");
			if (!repo && is_hydro_thunder(out.m_target))
				repo = find_global_by_rva(out, 0x359080);
			const auto* boats = find_global_by_class(out, "VuBoatManager");
			if (!boats && is_hydro_thunder(out.m_target))
				boats = find_global_by_rva(out, 0x358FB8);
			const auto* viewports = find_global_by_class(out, "VuViewportManager");
			if (!viewports && is_hydro_thunder(out.m_target))
				viewports = find_global_by_rva(out, 0x359060);
			const auto* entity = find_class(out, "VuEntity");
			const auto* transform = find_class(out, "VuTransformComponent");
			const auto* boat = find_class(out, "VuBoatEntity");

			const Types::property_info_t* entity_transform = entity ? find_property(*entity, "transform") : nullptr;
			if (!entity_transform && entity)
				entity_transform = find_property(*entity, "Transform");

			const Types::property_info_t* pos = transform ? find_property(*transform, "Position") : nullptr;
			if (!pos && transform)
				pos = find_property(*transform, "position");

			const Types::property_info_t* scale = transform ? find_property(*transform, "Scale") : nullptr;
			if (!scale && transform)
				scale = find_property(*transform, "scale");

			const Types::property_info_t* boost = boat ? find_property(*boat, "InitialBoostEnergy") : nullptr;
			if (!boost && boat)
				boost = find_property(*boat, "initial_boost_energy");

			const Types::property_info_t* entity_name = entity ? find_property(*entity, "Name") : nullptr;
			if (!entity_name && entity)
				entity_name = find_property(*entity, "name");

			const Types::property_info_t* props_list = entity ? find_property(*entity, "properties") : nullptr;
			if (!props_list && entity)
				props_list = find_property(*entity, "Properties");

			const Types::property_info_t* bucket_next = entity ? find_property(*entity, "bucket_next") : nullptr;
			const Types::property_info_t* buckets = nullptr;
			if (const auto* repo_cls = find_class(out, "VuEntityRepositoryImpl"))
				buckets = find_property(*repo_cls, "buckets");

			if (repo)
			{
				Types::pointer_chain_t chain{};
				chain.m_name = "world_entities";
				chain.m_description =
					"Dynamically resolved: VuEntityRepositoryImpl global -> entities -> transform/position "
					"(offsets come from property loaders / live rebind only).";

				add_step(chain, "entity_repository", "module",
					"read<" + repo->m_class_name + "*>(module + rva)",
					repo->m_rva, true);

				if (buckets)
				{
					add_step(chain, "bucket_array", "entity_repository",
						std::format("{} + 0x{:X}", repo->m_class_name, buckets->m_offset),
						buckets->m_offset);
				}

				if (bucket_next)
				{
					add_step(chain, "entity", "bucket_array[i]",
						std::format("follow chain via entity+0x{:X}", bucket_next->m_offset),
						bucket_next->m_offset);
				}

				if (entity_transform)
				{
					add_step(chain, "transform", "entity",
						std::format("read<VuTransformComponent*>(entity + 0x{:X})", entity_transform->m_offset),
						entity_transform->m_offset);
				}

				if (pos)
				{
					add_step(chain, "position", "transform",
						std::format("read<> (transform + 0x{:X}) \"{}\"", pos->m_offset, pos->m_name),
						pos->m_offset);
				}

				if (scale)
				{
					add_step(chain, "scale", "transform",
						std::format("read<> (transform + 0x{:X}) \"{}\"", scale->m_offset, scale->m_name),
						scale->m_offset);
				}

				if (chain.m_steps.size() > 1)
					out.m_chains.push_back(std::move(chain));
			}

			if (boats)
			{
				Types::pointer_chain_t chain{};
				chain.m_name = "boats";
				chain.m_description =
					"Dynamically resolved boat manager chain. Boost/name/transform steps only appear "
					"when those members were recovered from loaders or live property lists.";

				add_step(chain, "boat_manager", "module",
					"read<" + boats->m_class_name + "*>(module + rva)",
					boats->m_rva, true);

				if (const auto* bm = find_class(out, "VuBoatManager"))
				{
					if (const auto* data = find_property(*bm, "boats_data"))
					{
						add_step(chain, "boats_data", "boat_manager",
							std::format("read<>(boat_manager + 0x{:X})", data->m_offset),
							data->m_offset);
					}
					if (const auto* count = find_property(*bm, "boats_count"))
					{
						add_step(chain, "boats_count", "boat_manager",
							std::format("read<>(boat_manager + 0x{:X})", count->m_offset),
							count->m_offset);
					}
				}

				add_step(chain, "boat_entity", "boats_data[i]", "VuBoatEntity*", 0);

				if (entity_name)
				{
					add_step(chain, "name", "boat_entity",
						std::format("\"{}\" at +0x{:X}", entity_name->m_name, entity_name->m_offset),
						entity_name->m_offset);
				}

				if (boost)
				{
					add_step(chain, "boost", "boat_entity",
						std::format("\"{}\" at +0x{:X}", boost->m_name, boost->m_offset),
						boost->m_offset);
				}

				if (entity_transform)
				{
					add_step(chain, "transform", "boat_entity",
						std::format("entity + 0x{:X}", entity_transform->m_offset),
						entity_transform->m_offset);
				}

				if (pos)
				{
					add_step(chain, "position", "transform",
						std::format("\"{}\" at +0x{:X}", pos->m_name, pos->m_offset),
						pos->m_offset);
				}

				out.m_chains.push_back(std::move(chain));
			}

			if (viewports && is_hydro_thunder(out.m_target))
			{
				Types::pointer_chain_t chain{};
				chain.m_name = "camera";
				chain.m_description =
					"VuViewportManager::getCamera(i): embedded VuCamera at "
					"manager+0x28 + i*0x274 (size 0x240). Recovered from HydroThunder "
					"ctor sub_530B00, camera ctor sub_50BA20, and memcpy/FMOD sites.";

				add_step(chain, "viewport_manager", "module",
					"read<VuViewportManager*>(module + rva)",
					viewports->m_rva, true);

				add_step(chain, "viewport_count", "viewport_manager",
					std::format("read<int>(viewport_manager + 0x{:X})", k_viewport_count_off),
					k_viewport_count_off);

				add_step(chain, "camera", "viewport_manager",
					std::format("VuCamera* = viewport_manager + 0x{:X} + i*0x{:X}  // getCamera(i)",
						k_camera0_off, k_viewport_stride),
					k_camera0_off);

				add_step(chain, "eye", "camera",
					std::format("VuVector3 at camera + 0x{:X}  // FMOD listener / eye", k_cam_eye),
					k_cam_eye);

				add_step(chain, "view_matrix", "camera",
					std::format("VuMatrix4 at camera + 0x{:X}", k_cam_view),
					k_cam_view);

				add_step(chain, "proj_matrix", "camera",
					std::format("VuMatrix4 at camera + 0x{:X}", k_cam_proj),
					k_cam_proj);

				add_step(chain, "forward", "camera",
					std::format("VuVector3 at camera + 0x{:X}", k_cam_forward),
					k_cam_forward);

				add_step(chain, "up", "camera",
					std::format("VuVector3 at camera + 0x{:X}", k_cam_up),
					k_cam_up);

				out.m_chains.push_back(std::move(chain));
			}

			if (props_list)
			{
				Types::pointer_chain_t chain{};
				chain.m_name = "live_property_rebind";
				chain.m_description =
					"Walk live VuProperty lists on entities/components; member offset = value_ptr - owner. "
					"Property-list head offset itself was recovered dynamically.";

				add_step(chain, "prop_list", "owner",
					std::format("read<VuProperty*>(owner + 0x{:X})", props_list->m_offset),
					props_list->m_offset);
				out.m_chains.push_back(std::move(chain));
			}
		}
	};
}
