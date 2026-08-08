#pragma once

namespace Dumper
{
#pragma pack(push, 1)
	struct rtti_pmd_t
	{
		std::int32_t m_mdisp = 0;
		std::int32_t m_pdisp = 0;
		std::int32_t m_vdisp = 0;
	};

	struct rtti_type_descriptor_t
	{
		std::uint32_t m_vftable = 0;
		std::uint32_t m_spare = 0;
		// char m_name[];
	};

	struct rtti_base_class_descriptor_t
	{
		std::uint32_t m_type_descriptor = 0;
		std::uint32_t m_num_contained_bases = 0;
		rtti_pmd_t m_pmd{};
		std::uint32_t m_attributes = 0;
	};

	struct rtti_class_hierarchy_descriptor_t
	{
		std::uint32_t m_signature = 0;
		std::uint32_t m_attributes = 0;
		std::uint32_t m_num_base_classes = 0;
		std::uint32_t m_base_class_array = 0;
	};

	struct rtti_complete_object_locator_t
	{
		std::uint32_t m_signature = 0;
		std::uint32_t m_offset = 0;
		std::uint32_t m_cd_offset = 0;
		std::uint32_t m_type_descriptor = 0;
		std::uint32_t m_class_descriptor = 0;
	};
#pragma pack(pop)

	class c_rtti_scanner
	{
	public:
		[[nodiscard]] bool scan(const Pe::c_image& image, Types::dump_result_t& out)
		{
			m_image = &image;
			out.m_classes.clear();

			std::unordered_map<std::uint32_t, std::size_t> by_td;
			collect_type_descriptors(out, by_td);
			collect_complete_object_locators(out, by_td);

			out.m_rtti_count = out.m_classes.size();
			Logger::print("[c_rtti_scanner] scan: found %zu rtti classes", out.m_rtti_count);
			return !out.m_classes.empty();
		}

	private:
		const Pe::c_image* m_image = nullptr;

		void collect_type_descriptors(
			Types::dump_result_t& out,
			std::unordered_map<std::uint32_t, std::size_t>& by_td)
		{
			const auto size = m_image->size_of_image();
			for (std::uint32_t rva = 0; rva + 16 < size; ++rva)
			{
				const auto* bytes = m_image->data_rva(rva);
				if (!bytes)
					continue;

				// ".?AV" / ".?AU"
				if (bytes[0] != '.' || bytes[1] != '?' || bytes[2] != 'A')
					continue;
				if (bytes[3] != 'V' && bytes[3] != 'U')
					continue;

				if (rva < 8)
					continue;

				const auto td_rva = rva - 8;
				const auto td_va = m_image->rva_to_va(td_rva);
				const auto mangled = m_image->read_cstring_va(m_image->rva_to_va(rva), 512);
				if (mangled.empty())
					continue;

				const auto demangled = Common::demangle_msvc_class_name(mangled);
				if (demangled.empty())
					continue;

				Types::class_info_t info{};
				info.m_mangled_name = mangled;
				info.m_name = demangled;
				info.m_type_descriptor_va = td_va;
				info.m_is_struct = (bytes[3] == 'U');

				by_td.emplace(td_va, out.m_classes.size());
				out.m_classes.push_back(std::move(info));
			}
		}

		void collect_complete_object_locators(
			Types::dump_result_t& out,
			std::unordered_map<std::uint32_t, std::size_t>& by_td)
		{
			const auto size = m_image->size_of_image();
			std::vector<std::pair<std::uint32_t, std::size_t>> cols; // col_va, class_index

			for (std::uint32_t rva = 0; rva + sizeof(rtti_complete_object_locator_t) < size; rva += 4)
			{
				rtti_complete_object_locator_t col{};
				if (!m_image->read_bytes_rva(rva, &col, sizeof(col)))
					continue;

				if (col.m_signature != 0)
					continue;
				if (!m_image->contains_va(col.m_type_descriptor))
					continue;
				if (!m_image->contains_va(col.m_class_descriptor))
					continue;

				auto it = by_td.find(col.m_type_descriptor);
				if (it == by_td.end())
					continue;

				auto& info = out.m_classes[it->second];
				const auto col_va = m_image->rva_to_va(rva);

				if (info.m_col_va && col.m_offset != 0)
					continue;

				info.m_col_va = col_va;
				info.m_bases.clear();
				parse_hierarchy(col.m_class_descriptor, info);
				cols.emplace_back(col_va, it->second);
			}

			// Resolve vftables: scan image for `dd offset COL`, vftable starts at next dword.
			std::unordered_map<std::uint32_t, std::size_t> col_to_class;
			col_to_class.reserve(cols.size());
			for (const auto& [col_va, class_index] : cols)
				col_to_class.emplace(col_va, class_index);

			for (std::uint32_t rva = 0; rva + 8 < size; rva += 4)
			{
				const auto value = m_image->read_rva<std::uint32_t>(rva);
				auto it = col_to_class.find(value);
				if (it == col_to_class.end())
					continue;

				const auto maybe_fn = m_image->read_rva<std::uint32_t>(rva + 4);
				if (!m_image->contains_va(maybe_fn))
					continue;
				if (!m_image->section_is_executable(m_image->va_to_rva(maybe_fn)))
					continue;

				auto& info = out.m_classes[it->second];
				if (!info.m_vftable_va)
					info.m_vftable_va = m_image->rva_to_va(rva + 4);
			}

			std::size_t with_vf = 0;
			for (const auto& cls : out.m_classes)
			{
				if (cls.m_vftable_va)
					++with_vf;
			}
			Logger::print("[c_rtti_scanner] scan: vftables_resolved=%zu", with_vf);
		}

		void parse_hierarchy(std::uint32_t chd_va, Types::class_info_t& info)
		{
			const auto chd = m_image->read_va<rtti_class_hierarchy_descriptor_t>(chd_va);
			if (!chd.m_num_base_classes || chd.m_num_base_classes > 64)
				return;
			if (!m_image->contains_va(chd.m_base_class_array))
				return;

			for (std::uint32_t i = 0; i < chd.m_num_base_classes; ++i)
			{
				const auto bcd_va = m_image->read_va<std::uint32_t>(chd.m_base_class_array + i * 4);
				if (!m_image->contains_va(bcd_va))
					continue;

				const auto bcd = m_image->read_va<rtti_base_class_descriptor_t>(bcd_va);
				if (!m_image->contains_va(bcd.m_type_descriptor))
					continue;

				const auto name_va = bcd.m_type_descriptor + sizeof(rtti_type_descriptor_t);
				auto mangled = m_image->read_cstring_va(name_va, 512);
				auto demangled = Common::demangle_msvc_class_name(mangled);
				if (demangled.empty())
					continue;

				// Skip self entry (first base is usually the class itself)
				if (i == 0 && demangled == info.m_name)
					continue;

				Types::base_class_info_t base{};
				base.m_name = std::move(demangled);
				base.m_type_descriptor_va = bcd.m_type_descriptor;
				base.m_member_displacement = bcd.m_pmd.m_mdisp;
				base.m_attributes = bcd.m_attributes;
				info.m_bases.push_back(std::move(base));
			}
		}
	};
}
