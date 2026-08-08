#pragma once

namespace Dumper
{
	class c_sdk_emitter
	{
	public:
		[[nodiscard]] bool emit(const Types::dump_result_t& result, const std::filesystem::path& out_dir)
		{
			std::filesystem::create_directories(out_dir);
			std::filesystem::create_directories(out_dir / "SDK");

			const bool ok_types = emit_types_header(out_dir / "SDK" / "types.hpp");
			const bool ok_classes = emit_classes_header(result, out_dir / "SDK" / "classes.hpp");
			const bool ok_orphans = emit_orphan_loaders(result, out_dir / "SDK" / "orphan_loaders.hpp");
			const bool ok_engine = emit_engine_offsets(result, out_dir / "SDK" / "engine_offsets.hpp");
			const bool ok_summary = emit_summary(result, out_dir / "dump_summary.txt");
			const bool ok_json = emit_json(result, out_dir / "sdk.json");

			Logger::print("[c_sdk_emitter] emit: wrote SDK to %s", out_dir.string().c_str());
			return ok_types && ok_classes && ok_orphans && ok_engine && ok_summary && ok_json;
		}

	private:
		[[nodiscard]] static std::string cpp_member_name(const Types::property_info_t& prop)
		{
			return "m_" + Common::to_lower(prop.m_sanitized_name);
		}

		[[nodiscard]] static bool is_vu_class(const Types::class_info_t& cls)
		{
			if (Common::starts_with(cls.m_name, "loader_"))
				return false;
			if (cls.m_name.find("?$") != std::string::npos)
				return false;
			return Common::starts_with(cls.m_name, "Vu") || cls.m_name.find("@Vu") != std::string::npos;
		}

		[[nodiscard]] static std::string cpp_type_for(const Types::property_info_t& prop)
		{
			if (prop.m_kind == Types::property_kind_t::pointer && !prop.m_pointee_class.empty())
				return "c_" + Common::sanitize_identifier(prop.m_pointee_class) + "*";
			return Types::to_string(prop.m_kind);
		}

		[[nodiscard]] static std::string cpp_type_for_field(const Types::engine_field_t& field)
		{
			if (field.m_kind == Types::property_kind_t::pointer && !field.m_pointee_class.empty())
				return "c_" + Common::sanitize_identifier(field.m_pointee_class) + "*";
			return Types::to_string(field.m_kind);
		}

		[[nodiscard]] static std::uint32_t member_size(const Types::property_info_t& prop) noexcept
		{
			switch (prop.m_kind)
			{
			case Types::property_kind_t::bool8: return 1;
			case Types::property_kind_t::vector2: return 8;
			case Types::property_kind_t::vector: return 16; // VuVector3: xyz + pad
			case Types::property_kind_t::color: return 4;
			case Types::property_kind_t::rect: return 16;
			case Types::property_kind_t::int64: return 8;
			case Types::property_kind_t::matrix4: return 64;
			case Types::property_kind_t::pointer: return 4;
			case Types::property_kind_t::int32:
			case Types::property_kind_t::float32:
			case Types::property_kind_t::string:
			case Types::property_kind_t::asset:
				return 4;
			case Types::property_kind_t::custom:
				return 4;
			case Types::property_kind_t::unknown:
			default:
				// Emitted as std::uint8_t.
				return 1;
			}
		}

		[[nodiscard]] static bool is_byte_member(const Types::property_info_t& prop) noexcept
		{
			return prop.m_kind == Types::property_kind_t::bool8
				|| prop.m_kind == Types::property_kind_t::unknown;
		}

		// Loader noise often lands unresolved names at +0; those are not real packed bytes.
		[[nodiscard]] static bool is_packable_byte(const Types::property_info_t& prop) noexcept
		{
			if (!is_byte_member(prop))
				return false;
			if (prop.m_kind == Types::property_kind_t::bool8)
				return true;
			return prop.m_offset != 0;
		}

		[[nodiscard]] static std::string unique_member_name(
			const Types::property_info_t& prop,
			std::unordered_map<std::string, std::uint32_t>& used_names)
		{
			auto member = cpp_member_name(prop);
			auto& count = used_names[member];
			if (count > 0)
				member += "_" + std::to_string(count);
			++count;
			return member;
		}

		static void emit_byte_mask_comment(
			std::ofstream& out,
			const Types::property_info_t& prop,
			std::uint32_t align,
			std::string_view prefix,
			std::string_view member_name = {})
		{
			const auto lane = prop.m_offset & ~(align - 1);
			const auto byte_in_lane = prop.m_offset & (align - 1);
			const auto mask = 0xFFull << (byte_in_lane * 8);

			out << "\t\t// " << prefix;
			if (!member_name.empty())
				out << member_name << " ";
			out << "+0x" << std::hex << prop.m_offset << std::dec
				<< " \"" << prop.m_name << "\""
				<< " lane=0x" << std::hex << lane << std::dec
				<< " byte=" << byte_in_lane
				<< " mask=0x" << std::hex << mask << std::dec
				<< " shift=" << (byte_in_lane * 8);
			if (prop.m_loader_va)
				out << " loader=0x" << std::hex << prop.m_loader_va << std::dec;
			out << "\n";
		}

		static void emit_property_members(std::ofstream& out, const Types::class_info_t& cls)
		{
			constexpr std::uint32_t k_align = 8;

			const auto& props = cls.m_properties;
			std::uint32_t cursor = 0;
			std::unordered_map<std::string, std::uint32_t> used_names;
			std::unordered_set<std::size_t> emitted;

			auto emit_pad_to = [&](std::uint32_t target)
			{
				if (target <= cursor)
					return;
				const auto pad = target - cursor;
				out << "\t\tstd::uint8_t pad_0x" << std::hex << cursor << std::dec
					<< "[0x" << std::hex << pad << std::dec << "];\n";
				cursor = target;
			};

			for (std::size_t i = 0; i < props.size(); ++i)
			{
				if (emitted.contains(i))
					continue;

				const auto& prop = props[i];

				// Unresolved +0 unknowns: comment only (no storage).
				if (prop.m_kind == Types::property_kind_t::unknown && prop.m_offset == 0)
				{
					emit_byte_mask_comment(out, prop, k_align, "unresolved ");
					emitted.insert(i);
					continue;
				}

				if (prop.m_offset < cursor)
				{
					if (is_byte_member(prop))
						emit_byte_mask_comment(out, prop, k_align, "alias ");
					else
					{
						out << "\t\t// alias +0x" << std::hex << prop.m_offset << std::dec
							<< " \"" << prop.m_name << "\" (" << cpp_type_for(prop) << ")\n";
					}
					emitted.insert(i);
					continue;
				}

				// Pack 1-byte members that share an 8-byte aligned lane when 2+ distinct
				// byte slots are occupied (bitmask = 0xFF << (byte_index * 8)).
				if (is_packable_byte(prop))
				{
					const auto lane = prop.m_offset & ~(k_align - 1);
					std::vector<std::size_t> group;
					std::unordered_set<std::uint32_t> distinct_bytes;

					for (std::size_t j = i; j < props.size(); ++j)
					{
						if (emitted.contains(j))
							continue;
						const auto& candidate = props[j];
						if (candidate.m_offset >= lane + k_align)
							break;

						if (!is_packable_byte(candidate))
						{
							// Typed non-byte field inside this lane — fall back to normal emit.
							if ((candidate.m_offset & ~(k_align - 1)) == lane)
							{
								group.clear();
								break;
							}
							continue;
						}
						if ((candidate.m_offset & ~(k_align - 1)) != lane)
							continue;

						group.push_back(j);
						distinct_bytes.insert(candidate.m_offset - lane);
					}

					if (group.size() >= 2 && distinct_bytes.size() >= 2)
					{
						emit_pad_to(lane);

						std::uint64_t occupied = 0;
						for (const auto byte_i : distinct_bytes)
							occupied |= (0xFFull << (byte_i * 8));

						out << "\t\tstd::uint64_t m_pack_0x" << std::hex << lane << std::dec
							<< "; // 8-byte packed lane @ 0x" << std::hex << lane << std::dec
							<< " pack_mask=0x" << occupied << std::dec << "\n";

						for (const auto idx : group)
						{
							const auto& gprop = props[idx];
							emitted.insert(idx);
							const auto member = unique_member_name(gprop, used_names);
							emit_byte_mask_comment(out, gprop, k_align, "", member);
						}

						cursor = lane + k_align;
						continue;
					}
				}

				emit_pad_to(prop.m_offset);
				emitted.insert(i);

				const auto member = unique_member_name(prop, used_names);
				out << "\t\t" << cpp_type_for(prop) << " "
					<< member
					<< "; // 0x" << std::hex << prop.m_offset << std::dec
					<< " \"" << prop.m_name << "\"";

				if (is_byte_member(prop))
				{
					const auto byte_in_lane = prop.m_offset & (k_align - 1);
					const auto mask = 0xFFull << (byte_in_lane * 8);
					out << " lane=0x" << std::hex << (prop.m_offset & ~(k_align - 1)) << std::dec
						<< " byte=" << byte_in_lane
						<< " mask=0x" << std::hex << mask << std::dec
						<< " shift=" << (byte_in_lane * 8);
				}

				if (prop.m_loader_va)
					out << " loader=0x" << std::hex << prop.m_loader_va << std::dec;
				if (!prop.m_pointee_class.empty())
					out << " -> " << prop.m_pointee_class;

				out << "\n";
				cursor = prop.m_offset + member_size(prop);

				// Same-offset aliases that follow: annotate with lane/mask.
				for (std::size_t j = i + 1; j < props.size(); ++j)
				{
					if (emitted.contains(j))
						continue;
					const auto& alias = props[j];
					if (alias.m_offset != prop.m_offset)
						break;
					emitted.insert(j);
					if (is_byte_member(alias))
						emit_byte_mask_comment(out, alias, k_align, "alias ");
					else
					{
						out << "\t\t// alias +0x" << std::hex << alias.m_offset << std::dec
							<< " \"" << alias.m_name << "\" (" << cpp_type_for(alias) << ")\n";
					}
				}
			}
		}

		[[nodiscard]] bool emit_types_header(const std::filesystem::path& path)
		{
			std::ofstream out(path);
			if (!out)
				return false;

			out << "#pragma once\n";
			out << "// auto-generated by vu static sdk dumper\n\n";
			out << "#include <cstdint>\n\n";
			out << "namespace Vu::SDK\n{\n";
			out << "\tusing vu_string_t = char*;\n";
			out << "\tusing vu_asset_ref_t = void*;\n";
			out << "\tusing vu_custom_t = std::uint8_t;\n\n";
			out << "\t// Engine math types (from VuBasicProperty<VuVectorN> / live size).\n";
			out << "\tstruct VuVector2\n";
			out << "\t{\n";
			out << "\t\tfloat x{}, y{};\n";
			out << "\t};\n";
			out << "\tstatic_assert(sizeof(VuVector2) == 8);\n\n";
			out << "\tstruct VuVector3\n";
			out << "\t{\n";
			out << "\t\tfloat x{}, y{}, z{};\n";
			out << "\t\tfloat pad{}; // storage is 16 bytes (property copies two QWORDs)\n";
			out << "\t};\n";
			out << "\tstatic_assert(sizeof(VuVector3) == 16);\n\n";
			out << "\tstruct VuColor\n";
			out << "\t{\n";
			out << "\t\tstd::uint8_t r{}, g{}, b{}, a{};\n";
			out << "\t};\n";
			out << "\tstatic_assert(sizeof(VuColor) == 4);\n\n";
			out << "\tstruct VuRect\n";
			out << "\t{\n";
			out << "\t\tfloat left{}, top{}, right{}, bottom{};\n";
			out << "\t};\n";
			out << "\tstatic_assert(sizeof(VuRect) == 16);\n\n";
			out << "\tstruct VuMatrix4\n";
			out << "\t{\n";
			out << "\t\tfloat m[16];\n";
			out << "\t};\n\n";
			out << "\tusing vu_vector_t = VuVector3; // backward-compatible alias\n";
			out << "\tusing vu_matrix4_t = VuMatrix4;\n\n";
			out << "\t// 8-byte packed lane helpers (byte members share an aligned uint64_t).\n";
			out << "\t[[nodiscard]] constexpr std::uint64_t vu_byte_mask(std::uint32_t byte_index) noexcept\n";
			out << "\t{\n";
			out << "\t\treturn 0xFFull << (byte_index * 8u);\n";
			out << "\t}\n";
			out << "\t[[nodiscard]] constexpr std::uint8_t vu_pack_get(std::uint64_t pack, std::uint32_t byte_index) noexcept\n";
			out << "\t{\n";
			out << "\t\treturn static_cast<std::uint8_t>((pack >> (byte_index * 8u)) & 0xFFu);\n";
			out << "\t}\n";
			out << "\tconstexpr void vu_pack_set(std::uint64_t& pack, std::uint32_t byte_index, std::uint8_t value) noexcept\n";
			out << "\t{\n";
			out << "\t\tconst auto shift = byte_index * 8u;\n";
			out << "\t\tpack = (pack & ~(0xFFull << shift)) | (static_cast<std::uint64_t>(value) << shift);\n";
			out << "\t}\n";
			out << "}\n";
			return true;
		}

		[[nodiscard]] bool emit_engine_offsets(const Types::dump_result_t& result, const std::filesystem::path& path)
		{
			std::ofstream out(path);
			if (!out)
				return false;

			const auto image_base = result.m_image_base ? result.m_image_base : 0x400000u;

			out << "#pragma once\n";
			out << "// auto-generated by vu hybrid sdk dumper\n";
			out << "// static PE + IDA-derived engine model (+ optional live validation)\n\n";
			out << "#include <cstdint>\n\n";
			out << "namespace Vu::SDK::Engine\n{\n";
			out << "\tconstexpr std::uint32_t k_image_base = 0x" << std::hex << image_base << std::dec << ";\n\n";

			out << "\tnamespace Globals\n\t{\n";
			for (const auto& g : result.m_globals)
			{
				out << "\t\tconstexpr std::uint32_t "
					<< Common::sanitize_identifier(g.m_name)
					<< " = 0x" << std::hex << g.m_rva << std::dec
					<< "; // va=0x" << std::hex << g.m_va << std::dec;
				if (!g.m_class_name.empty())
					out << " " << g.m_class_name;
				if (!g.m_source.empty())
					out << " [" << g.m_source << "]";
				out << "\n";
			}
			if (result.m_globals.empty())
				out << "\t\t// none discovered\n";
			out << "\t}\n\n";

			out << "\tnamespace Fields\n\t{\n";
			for (const auto& f : result.m_engine_fields)
			{
				out << "\t\tconstexpr std::uint32_t "
					<< Common::sanitize_identifier(f.m_owner) << "_"
					<< Common::sanitize_identifier(f.m_name)
					<< " = 0x" << std::hex << f.m_offset << std::dec
					<< "; // " << cpp_type_for_field(f);
				if (!f.m_pointee_class.empty() && f.m_kind == Types::property_kind_t::pointer)
					out << " -> " << f.m_pointee_class;
				if (!f.m_note.empty())
					out << " -- " << f.m_note;
				out << "\n";
			}
			out << "\t}\n\n";

			out << "\tnamespace Chains\n\t{\n";
			for (const auto& chain : result.m_chains)
			{
				out << "\t\t// " << chain.m_name << "\n";
				out << "\t\t// " << chain.m_description << "\n";
				for (std::size_t i = 0; i < chain.m_steps.size(); ++i)
				{
					const auto& s = chain.m_steps[i];
					out << "\t\t//   [" << i << "] " << s.m_label
						<< " <- " << s.m_from
						<< " | " << s.m_how;
					if (s.m_offset_or_rva || s.m_is_global_rva)
					{
						out << " (0x" << std::hex << s.m_offset_or_rva << std::dec;
						out << (s.m_is_global_rva ? " rva)" : ")");
					}
					out << "\n";
				}
				out << "\n";
			}
			out << "\t}\n";
			out << "}\n";
			return true;
		}

		[[nodiscard]] bool emit_classes_header(const Types::dump_result_t& result, const std::filesystem::path& path)
		{
			std::ofstream out(path);
			if (!out)
				return false;

			out << "#pragma once\n";
			out << "// auto-generated by vu static sdk dumper\n\n";
			out << "#include <cstdint>\n";
			out << "#include \"types.hpp\"\n\n";
			out << "namespace Vu::SDK\n{\n";

			// Forward-declare so typed pointer members can reference later classes.
			for (const auto& cls : result.m_classes)
			{
				if (!is_vu_class(cls))
					continue;
				const auto type_kw = cls.m_is_struct ? "struct" : "class";
				out << "\t" << type_kw << " c_" << Common::sanitize_identifier(cls.m_name) << ";\n";
			}
			out << "\n";

			for (const auto& cls : result.m_classes)
			{
				if (!is_vu_class(cls))
					continue;

				const auto type_kw = cls.m_is_struct ? "struct" : "class";
				out << "\t" << type_kw << " c_" << Common::sanitize_identifier(cls.m_name);

				std::vector<std::string> bases;
				for (const auto& base : cls.m_bases)
				{
					if (base.m_name.find("?$") != std::string::npos)
						continue;
					if (!(Common::starts_with(base.m_name, "Vu") || base.m_name.find("@Vu") != std::string::npos))
						continue;
					bases.push_back("c_" + Common::sanitize_identifier(base.m_name));
				}

				if (!bases.empty())
				{
					out << " : ";
					for (std::size_t i = 0; i < bases.size(); ++i)
					{
						if (i)
							out << ", ";
						out << "public " << bases[i];
					}
				}

				out << "\n\t{\n";
				out << "\tpublic:\n";
				out << "\t\t// mangled: " << cls.m_mangled_name << "\n";
				out << "\t\t// type_descriptor: 0x" << std::hex << cls.m_type_descriptor_va << std::dec << "\n";
				if (cls.m_vftable_va)
					out << "\t\t// vftable: 0x" << std::hex << cls.m_vftable_va << std::dec << "\n";

				for (const auto& base : cls.m_bases)
				{
					out << "\t\t// base " << base.m_name
						<< " mdisp=0x" << std::hex << base.m_member_displacement << std::dec << "\n";
				}

				if (!cls.m_properties.empty())
				{
					out << "\n";
					emit_property_members(out, cls);
				}

				out << "\t};\n\n";
			}

			out << "}\n";
			return true;
		}

		[[nodiscard]] bool emit_orphan_loaders(const Types::dump_result_t& result, const std::filesystem::path& path)
		{
			std::ofstream out(path);
			if (!out)
				return false;

			out << "#pragma once\n";
			out << "// auto-generated by vu static sdk dumper\n";
			out << "// property loaders that could not be bound to an RTTI class\n\n";
			out << "#include <cstdint>\n";
			out << "#include \"types.hpp\"\n\n";
			out << "namespace Vu::SDK::Orphans\n{\n";

			bool any = false;
			for (const auto& cls : result.m_classes)
			{
				if (!Common::starts_with(cls.m_name, "loader_") || cls.m_properties.empty())
					continue;

				any = true;
				out << "\tstruct " << Common::sanitize_identifier(cls.m_name) << "_t\n";
				out << "\t{\n";
				emit_property_members(out, cls);
				out << "\t};\n\n";
			}

			if (!any)
				out << "\t// none\n";

			out << "}\n";
			return true;
		}

		[[nodiscard]] bool emit_summary(const Types::dump_result_t& result, const std::filesystem::path& path)
		{
			std::ofstream out(path);
			if (!out)
				return false;

			std::size_t bound_classes = 0;
			std::size_t bound_props = 0;
			std::size_t orphan_loaders = 0;

			for (const auto& cls : result.m_classes)
			{
				if (Common::starts_with(cls.m_name, "loader_"))
				{
					if (!cls.m_properties.empty())
						++orphan_loaders;
					continue;
				}
				if (!cls.m_properties.empty())
				{
					++bound_classes;
					bound_props += cls.m_properties.size();
				}
			}

			out << "vu hybrid sdk dump summary\n";
			out << "rtti_classes: " << result.m_rtti_count << "\n";
			out << "total_classes: " << result.m_classes.size() << "\n";
			out << "properties: " << result.m_property_count << "\n";
			out << "bound_classes: " << bound_classes << "\n";
			out << "bound_properties: " << bound_props << "\n";
			out << "orphan_loaders: " << orphan_loaders << "\n";
			out << "globals: " << result.m_globals.size() << "\n";
			out << "engine_fields: " << result.m_engine_fields.size() << "\n";
			out << "pointer_chains: " << result.m_chains.size() << "\n";
			out << "live_rebound: " << result.m_live_rebound_count << "\n";
			out << "live_orphan_assigned: " << result.m_live_orphan_assigned << "\n";
			out << "live_cameras: " << result.m_live_cameras.size() << "\n";
			out << "target: " << result.m_target.m_name
				<< " (" << to_string(result.m_target.m_id) << ")\n";
			out << "get_property: 0x" << std::hex << result.m_get_property_va << std::dec << "\n";
			out << "image_base: 0x" << std::hex << result.m_image_base << std::dec << "\n\n";

			out << "live_camera_angles:\n";
			if (result.m_live_cameras.empty())
			{
				out << "  (none -- run with --live while the target process is running)\n";
			}
			else
			{
				out << std::fixed << std::setprecision(3);
				for (const auto& cam : result.m_live_cameras)
				{
					if (!cam.m_valid)
						continue;
					out << "  viewport[" << cam.m_viewport_index << "/" << cam.m_viewport_count << "]"
						<< " manager=0x" << std::hex << cam.m_manager
						<< " camera=0x" << cam.m_camera << std::dec << "\n";
					out << "    eye=(" << cam.m_eye[0] << ", " << cam.m_eye[1] << ", " << cam.m_eye[2] << ")\n";
					out << "    forward=(" << cam.m_forward[0] << ", " << cam.m_forward[1] << ", " << cam.m_forward[2] << ")\n";
					out << "    up=(" << cam.m_up[0] << ", " << cam.m_up[1] << ", " << cam.m_up[2] << ")\n";
					out << "    yaw_deg=" << cam.m_yaw_deg
						<< " pitch_deg=" << cam.m_pitch_deg
						<< " roll_deg=" << cam.m_roll_deg << "\n";
				}
				out << std::defaultfloat;
			}
			out << "\n";

			out << "pointer_chains:\n";
			for (const auto& chain : result.m_chains)
			{
				out << "  " << chain.m_name << " -- " << chain.m_description << "\n";
				for (std::size_t i = 0; i < chain.m_steps.size(); ++i)
				{
					const auto& s = chain.m_steps[i];
					out << "    [" << i << "] " << s.m_label
						<< " <- " << s.m_from
						<< " | " << s.m_how << "\n";
				}
			}
			out << "\n";

			out << "globals:\n";
			for (const auto& g : result.m_globals)
			{
				out << "  0x" << std::hex << g.m_va << std::dec
					<< " rva=0x" << std::hex << g.m_rva << std::dec
					<< " " << g.m_name;
				if (!g.m_class_name.empty())
					out << " -> " << g.m_class_name;
				out << " [" << g.m_source << "]\n";
			}
			out << "\nengine_fields:\n";
			for (const auto& f : result.m_engine_fields)
			{
				out << "  " << f.m_owner << "::" << f.m_name
					<< " +0x" << std::hex << f.m_offset << std::dec
					<< " (" << Types::to_string(f.m_kind) << ") " << f.m_note << "\n";
			}
			out << "\n";

			for (const auto& cls : result.m_classes)
			{
				if (cls.m_properties.empty() && Common::starts_with(cls.m_name, "loader_"))
					continue;

				out << cls.m_name;
				if (!cls.m_bases.empty())
				{
					out << " : ";
					for (std::size_t i = 0; i < cls.m_bases.size(); ++i)
					{
						if (i)
							out << ", ";
						out << cls.m_bases[i].m_name;
					}
				}
				out << "\n";

				for (const auto& prop : cls.m_properties)
				{
					out << "  +0x" << std::hex << prop.m_offset << std::dec
						<< " " << prop.m_name
						<< " (" << Types::to_string(prop.m_kind) << ")\n";
				}
			}

			return true;
		}

		[[nodiscard]] bool emit_json(const Types::dump_result_t& result, const std::filesystem::path& path)
		{
			std::ofstream out(path);
			if (!out)
				return false;

			auto esc = [](const std::string& s)
			{
				std::string r;
				r.reserve(s.size());
				for (char c : s)
				{
					switch (c)
					{
					case '\\': r += "\\\\"; break;
					case '"': r += "\\\""; break;
					case '\n': r += "\\n"; break;
					case '\r': r += "\\r"; break;
					case '\t': r += "\\t"; break;
					default: r.push_back(c); break;
					}
				}
				return r;
			};

			out << "{\n";
			out << "  \"get_property\": \"0x" << std::hex << result.m_get_property_va << std::dec << "\",\n";
			out << "  \"image_base\": \"0x" << std::hex << result.m_image_base << std::dec << "\",\n";
			out << "  \"rtti_count\": " << result.m_rtti_count << ",\n";
			out << "  \"property_count\": " << result.m_property_count << ",\n";
			out << "  \"globals\": [\n";
			for (std::size_t i = 0; i < result.m_globals.size(); ++i)
			{
				const auto& g = result.m_globals[i];
				out << "    {\"name\":\"" << esc(g.m_name)
					<< "\",\"class\":\"" << esc(g.m_class_name)
					<< "\",\"va\":\"0x" << std::hex << g.m_va
					<< "\",\"rva\":\"0x" << g.m_rva << std::dec
					<< "\",\"source\":\"" << esc(g.m_source) << "\"}";
				if (i + 1 < result.m_globals.size())
					out << ",";
				out << "\n";
			}
			out << "  ],\n";
			out << "  \"engine_fields\": [\n";
			for (std::size_t i = 0; i < result.m_engine_fields.size(); ++i)
			{
				const auto& f = result.m_engine_fields[i];
				out << "    {\"owner\":\"" << esc(f.m_owner)
					<< "\",\"name\":\"" << esc(f.m_name)
					<< "\",\"offset\":" << f.m_offset
					<< ",\"type\":\"" << esc(cpp_type_for_field(f))
					<< "\",\"pointee\":\"" << esc(f.m_pointee_class)
					<< "\",\"note\":\"" << esc(f.m_note) << "\"}";
				if (i + 1 < result.m_engine_fields.size())
					out << ",";
				out << "\n";
			}
			out << "  ],\n";
			out << "  \"chains\": [\n";
			for (std::size_t i = 0; i < result.m_chains.size(); ++i)
			{
				const auto& chain = result.m_chains[i];
				out << "    {\"name\":\"" << esc(chain.m_name)
					<< "\",\"description\":\"" << esc(chain.m_description)
					<< "\",\"steps\":[";
				for (std::size_t s = 0; s < chain.m_steps.size(); ++s)
				{
					const auto& step = chain.m_steps[s];
					if (s)
						out << ",";
					out << "{\"label\":\"" << esc(step.m_label)
						<< "\",\"from\":\"" << esc(step.m_from)
						<< "\",\"how\":\"" << esc(step.m_how)
						<< "\",\"value\":" << step.m_offset_or_rva
						<< ",\"is_rva\":" << (step.m_is_global_rva ? "true" : "false") << "}";
				}
				out << "]}";
				if (i + 1 < result.m_chains.size())
					out << ",";
				out << "\n";
			}
			out << "  ],\n";
			out << "  \"classes\": [\n";

			for (std::size_t i = 0; i < result.m_classes.size(); ++i)
			{
				const auto& cls = result.m_classes[i];
				out << "    {\n";
				out << "      \"name\": \"" << esc(cls.m_name) << "\",\n";
				out << "      \"mangled\": \"" << esc(cls.m_mangled_name) << "\",\n";
				out << "      \"type_descriptor\": \"0x" << std::hex << cls.m_type_descriptor_va << std::dec << "\",\n";
				out << "      \"vftable\": \"0x" << std::hex << cls.m_vftable_va << std::dec << "\",\n";
				out << "      \"bases\": [";
				for (std::size_t b = 0; b < cls.m_bases.size(); ++b)
				{
					if (b)
						out << ", ";
					out << "\"" << esc(cls.m_bases[b].m_name) << "\"";
				}
				out << "],\n";
				out << "      \"properties\": [\n";
				for (std::size_t p = 0; p < cls.m_properties.size(); ++p)
				{
					const auto& prop = cls.m_properties[p];
					out << "        {\"name\":\"" << esc(prop.m_name)
						<< "\",\"offset\":" << prop.m_offset
						<< ",\"type\":\"" << esc(cpp_type_for(prop))
						<< "\",\"pointee\":\"" << esc(prop.m_pointee_class)
						<< "\",\"loader\":\"0x" << std::hex << prop.m_loader_va << std::dec << "\"}";
					if (p + 1 < cls.m_properties.size())
						out << ",";
					out << "\n";
				}
				out << "      ]\n";
				out << "    }";
				if (i + 1 < result.m_classes.size())
					out << ",";
				out << "\n";
			}

			out << "  ]\n";
			out << "}\n";
			return true;
		}
	};
}
