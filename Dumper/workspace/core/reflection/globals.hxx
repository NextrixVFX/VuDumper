#pragma once

namespace Dumper
{
	class c_globals_scanner
	{
	public:
		[[nodiscard]] bool scan(const Pe::c_image& image, Types::dump_result_t& out)
		{
			m_image = &image;
			out.m_image_base = image.image_base();

			std::unordered_map<std::uint32_t, std::size_t> vftable_to_class;
			for (std::size_t i = 0; i < out.m_classes.size(); ++i)
			{
				if (out.m_classes[i].m_vftable_va)
					vftable_to_class.emplace(out.m_classes[i].m_vftable_va, i);
			}

			if (vftable_to_class.empty())
			{
				Logger::warn("[c_globals_scanner] scan: no vftables available");
				return false;
			}

			scan_absolute_pointer_stores(out, vftable_to_class);
			if (is_hydro_thunder(out.m_target))
				scan_system_init_cluster(out, vftable_to_class);

			std::sort(out.m_globals.begin(), out.m_globals.end(),
				[](const Types::global_info_t& a, const Types::global_info_t& b)
				{
					return a.m_va < b.m_va;
				});

			out.m_globals.erase(
				std::unique(out.m_globals.begin(), out.m_globals.end(),
					[](const Types::global_info_t& a, const Types::global_info_t& b)
					{
						return a.m_va == b.m_va;
					}),
				out.m_globals.end());

			Logger::print("[c_globals_scanner] scan: globals=%zu", out.m_globals.size());
			return !out.m_globals.empty();
		}

	private:
		const Pe::c_image* m_image = nullptr;

		[[nodiscard]] bool is_plausible_global_va(std::uint32_t va) const
		{
			if (!m_image->contains_va(va))
				return false;

			const auto rva = m_image->va_to_rva(va);
			if (m_image->section_is_executable(rva))
				return false;

			// Prefer writable / data-like sections (.data / .bss).
			for (const auto& s : m_image->sections())
			{
				const auto end = s.m_virtual_address + (std::max)(s.m_virtual_size, s.m_raw_size);
				if (rva < s.m_virtual_address || rva >= end)
					continue;

				const bool writable = (s.m_characteristics & IMAGE_SCN_MEM_WRITE) != 0;
				const bool readable = (s.m_characteristics & IMAGE_SCN_MEM_READ) != 0;
				return writable || readable;
			}
			return false;
		}

		void add_global(
			Types::dump_result_t& out,
			std::uint32_t global_va,
			std::uint32_t write_va,
			const Types::class_info_t* cls,
			std::string source)
		{
			if (!is_plausible_global_va(global_va))
				return;

			for (const auto& existing : out.m_globals)
			{
				if (existing.m_va == global_va)
					return;
			}

			Types::global_info_t g{};
			g.m_va = global_va;
			g.m_rva = m_image->va_to_rva(global_va);
			g.m_write_site_va = write_va;
			g.m_source = std::move(source);

			if (cls)
			{
				g.m_class_name = cls->m_name;
				g.m_vftable_va = cls->m_vftable_va;
				g.m_name = "g_" + Common::to_lower(Common::sanitize_identifier(cls->m_name));
			}
			else
			{
				g.m_name = std::format("g_unk_{:08X}", global_va);
			}

			out.m_globals.push_back(std::move(g));
		}

		void scan_absolute_pointer_stores(
			Types::dump_result_t& out,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class)
		{
			const auto size = m_image->size_of_image();
			std::uint32_t last_vftable = 0;
			std::size_t last_class = static_cast<std::size_t>(-1);
			std::uint32_t last_vftable_site = 0;

			for (std::uint32_t rva = 0; rva + 6 < size; ++rva)
			{
				if (!m_image->section_is_executable(rva))
				{
					last_vftable = 0;
					last_class = static_cast<std::size_t>(-1);
					continue;
				}

				const auto* b = m_image->data_rva(rva);
				if (!b)
					continue;

				// mov dword ptr [reg], imm32  (C7 00/01/02/03/06/07 imm)
				// or mov dword ptr [reg+disp8], imm32
				if (b[0] == 0xC7)
				{
					const auto mod = (b[1] >> 6) & 3;
					const auto reg = (b[1] >> 3) & 7;
					const auto rm = b[1] & 7;
					if (reg == 0 && rm != 4)
					{
						std::uint32_t imm_at = 0;
						if (mod == 0 && rm != 5)
							imm_at = 2;
						else if (mod == 1)
							imm_at = 3;
						else if (mod == 2)
							imm_at = 6;

						if (imm_at && rva + imm_at + 4 < size)
						{
							std::uint32_t imm = 0;
							std::memcpy(&imm, b + imm_at, 4);
							if (auto it = vftable_to_class.find(imm); it != vftable_to_class.end())
							{
								last_vftable = imm;
								last_class = it->second;
								last_vftable_site = m_image->rva_to_va(rva);
							}
						}
					}
				}

				// mov reg, imm32 where imm is vftable (B8+r)
				if ((b[0] & 0xF8) == 0xB8)
				{
					std::uint32_t imm = 0;
					std::memcpy(&imm, b + 1, 4);
					if (auto it = vftable_to_class.find(imm); it != vftable_to_class.end())
					{
						last_vftable = imm;
						last_class = it->second;
						last_vftable_site = m_image->rva_to_va(rva);
					}
				}

				// Absolute store of register into global:
				// A3 xx xx xx xx          mov ds:imm32, eax
				// 89 0D / 15 / 1D / 35 / 3D xx xx xx xx  mov ds:imm32, ecx/edx/ebx/esi/edi
				std::uint32_t global_va = 0;
				std::uint32_t insn_len = 0;

				if (b[0] == 0xA3)
				{
					std::memcpy(&global_va, b + 1, 4);
					insn_len = 5;
				}
				else if (b[0] == 0x89 && (b[1] == 0x0D || b[1] == 0x15 || b[1] == 0x1D || b[1] == 0x35 || b[1] == 0x3D))
				{
					std::memcpy(&global_va, b + 2, 4);
					insn_len = 6;
				}

				if (!insn_len || !global_va)
					continue;

				const auto write_va = m_image->rva_to_va(rva);
				const Types::class_info_t* cls = nullptr;
				if (last_class != static_cast<std::size_t>(-1)
					&& last_vftable_site
					&& write_va >= last_vftable_site
					&& write_va - last_vftable_site < 0x80)
				{
					cls = &out.m_classes[last_class];
				}

				// Prefer manager / system-ish types when unbound store is in the singleton cluster.
				if (!cls && global_va >= 0x758F80 && global_va < 0x759100)
				{
					add_global(out, global_va, write_va, nullptr, "abs_store_cluster");
					(void)last_vftable;
					continue;
				}

				if (cls)
					add_global(out, global_va, write_va, cls, "vftable_then_abs_store");
			}
		}

		void scan_system_init_cluster(
			Types::dump_result_t& out,
			const std::unordered_map<std::uint32_t, std::size_t>& vftable_to_class)
		{
			// HydroThunder-only: system bootstrap (sub_4024E0) wires many manager singletons.
			// Capture every abs store in that function window and bind when a nearby
			// vftable imm matches an RTTI class.
			constexpr std::uint32_t k_init_va = 0x4024E0;
			constexpr std::uint32_t k_init_size = 0x5F9;

			if (!m_image->contains_va(k_init_va))
				return;

			const auto start_rva = m_image->va_to_rva(k_init_va);
			const auto end_rva = start_rva + k_init_size;
			std::uint32_t pending_vftable = 0;
			std::size_t pending_class = static_cast<std::size_t>(-1);

			for (std::uint32_t rva = start_rva; rva + 6 < end_rva; ++rva)
			{
				const auto* b = m_image->data_rva(rva);
				if (!b)
					continue;

				if (b[0] == 0xC7 && ((b[1] & 0xC7) == 0x00 || (b[1] & 0xC7) == 0x01 || (b[1] & 0xC7) == 0x02 || (b[1] & 0xC7) == 0x06))
				{
					std::uint32_t imm = 0;
					const auto mod = (b[1] >> 6) & 3;
					std::uint32_t imm_at = (mod == 0) ? 2 : (mod == 1 ? 3 : 0);
					if (imm_at && rva + imm_at + 4 < end_rva)
					{
						std::memcpy(&imm, b + imm_at, 4);
						if (auto it = vftable_to_class.find(imm); it != vftable_to_class.end())
						{
							pending_vftable = imm;
							pending_class = it->second;
						}
					}
				}

				std::uint32_t global_va = 0;
				if (b[0] == 0xA3)
					std::memcpy(&global_va, b + 1, 4);
				else if (b[0] == 0x89 && (b[1] == 0x0D || b[1] == 0x15 || b[1] == 0x1D || b[1] == 0x35 || b[1] == 0x3D))
					std::memcpy(&global_va, b + 2, 4);

				if (!global_va)
					continue;

				const Types::class_info_t* cls = nullptr;
				if (pending_class != static_cast<std::size_t>(-1))
					cls = &out.m_classes[pending_class];

				add_global(out, global_va, m_image->rva_to_va(rva), cls, "system_init");
				pending_vftable = 0;
				pending_class = static_cast<std::size_t>(-1);
				(void)pending_vftable;
			}
		}
	};
}
