#pragma once

namespace Dumper::Types
{
	enum class property_kind_t : std::uint8_t
	{
		unknown = 0,
		int32,
		float32,
		string,
		int64,
		asset,
		vector,   // VuVector3 (12 floats used, 16 bytes stored)
		vector2,  // VuVector2
		bool8,
		pointer,
		matrix4,
		color,    // VuColor
		rect,     // VuRect
		custom
	};

	[[nodiscard]] inline const char* to_string(property_kind_t kind) noexcept
	{
		switch (kind)
		{
		case property_kind_t::int32: return "int32_t";
		case property_kind_t::float32: return "float";
		case property_kind_t::string: return "vu_string_t";
		case property_kind_t::int64: return "int64_t";
		case property_kind_t::asset: return "vu_asset_ref_t";
		case property_kind_t::vector: return "VuVector3";
		case property_kind_t::vector2: return "VuVector2";
		case property_kind_t::bool8: return "bool";
		case property_kind_t::pointer: return "void*";
		case property_kind_t::matrix4: return "VuMatrix4";
		case property_kind_t::color: return "VuColor";
		case property_kind_t::rect: return "VuRect";
		case property_kind_t::custom: return "vu_custom_t";
		default: return "std::uint8_t";
		}
	}

	// Tags from VuBasicProperty<T, Tag> RTTI NTTP:
	//   0 int/float, 1 bool, 2 string, 5 VuColor, 6 VuVector2, 7 VuVector3, 8 VuRect
	// Note: getType() on Vector2/Vector3 properties returns 7/8 (off-by-one vs NTTP).
	[[nodiscard]] inline property_kind_t property_kind_from_tag(std::uint32_t tag) noexcept
	{
		switch (tag)
		{
		case 0: return property_kind_t::int32;
		case 1: return property_kind_t::bool8;
		case 2: return property_kind_t::string;
		case 5: return property_kind_t::color;
		case 6: return property_kind_t::vector2;
		case 7: return property_kind_t::vector; // VuVector3
		case 8: return property_kind_t::rect;
		default: return property_kind_t::unknown;
		}
	}

	struct property_info_t
	{
		std::string m_name{};
		std::string m_sanitized_name{};
		std::uint32_t m_offset = 0;
		property_kind_t m_kind = property_kind_t::unknown;
		std::uint32_t m_type_tag = 0;
		std::uint32_t m_name_va = 0;
		std::uint32_t m_loader_va = 0;
		bool m_from_engine_model = false;
		// When m_kind == pointer, optional RTTI class name for the pointee (e.g. "VuTransformComponent").
		std::string m_pointee_class{};
	};

	struct base_class_info_t
	{
		std::string m_name{};
		std::uint32_t m_type_descriptor_va = 0;
		std::int32_t m_member_displacement = 0;
		std::uint32_t m_attributes = 0;
	};

	struct class_info_t
	{
		std::string m_mangled_name{};
		std::string m_name{};
		std::uint32_t m_type_descriptor_va = 0;
		std::uint32_t m_col_va = 0;
		std::uint32_t m_vftable_va = 0;
		std::vector<base_class_info_t> m_bases{};
		std::vector<property_info_t> m_properties{};
		bool m_is_struct = false;
	};

	struct global_info_t
	{
		std::string m_name{};
		std::string m_class_name{};
		std::uint32_t m_va = 0;
		std::uint32_t m_rva = 0;
		std::uint32_t m_vftable_va = 0;
		std::uint32_t m_write_site_va = 0;
		std::string m_source{};
	};

	struct engine_field_t
	{
		std::string m_owner{};
		std::string m_name{};
		std::uint32_t m_offset = 0;
		property_kind_t m_kind = property_kind_t::unknown;
		std::string m_note{};
		// When m_kind == pointer, concrete pointee RTTI name (emitted as c_Name*).
		std::string m_pointee_class{};
	};

	struct pointer_chain_step_t
	{
		std::string m_label{};
		std::string m_from{};
		std::string m_how{};
		std::uint32_t m_offset_or_rva = 0;
		bool m_is_global_rva = false;
	};

	struct pointer_chain_t
	{
		std::string m_name{};
		std::string m_description{};
		std::vector<pointer_chain_step_t> m_steps{};
	};

	struct live_camera_t
	{
		bool m_valid = false;
		std::uint32_t m_viewport_index = 0;
		std::uint32_t m_viewport_count = 0;
		std::uint32_t m_manager = 0;
		std::uint32_t m_camera = 0;
		float m_eye[3]{};
		float m_forward[3]{};
		float m_up[3]{};
		float m_yaw_deg = 0.f;
		float m_pitch_deg = 0.f;
		float m_roll_deg = 0.f;
	};

	struct dump_result_t
	{
		target_profile_t m_target{};
		std::vector<class_info_t> m_classes{};
		std::vector<global_info_t> m_globals{};
		std::vector<engine_field_t> m_engine_fields{};
		std::vector<pointer_chain_t> m_chains{};
		std::vector<live_camera_t> m_live_cameras{};
		std::uint32_t m_get_property_va = 0;
		std::uint32_t m_image_base = 0;
		std::size_t m_property_count = 0;
		std::size_t m_rtti_count = 0;
		std::size_t m_live_rebound_count = 0;
		std::size_t m_live_orphan_assigned = 0;
	};
}
