#pragma once

namespace Dumper::Pe
{
	struct section_t
	{
		std::string m_name{};
		std::uint32_t m_virtual_address = 0;
		std::uint32_t m_virtual_size = 0;
		std::uint32_t m_raw_ptr = 0;
		std::uint32_t m_raw_size = 0;
		std::uint32_t m_characteristics = 0;
	};

	class c_image
	{
	public:
		bool load(const std::filesystem::path& path)
		{
			m_path = path;

			std::ifstream file(path, std::ios::binary | std::ios::ate);
			if (!file)
			{
				Logger::error("[c_image] load: failed to open input");
				return false;
			}

			const auto size = static_cast<std::size_t>(file.tellg());
			if (size < sizeof(IMAGE_DOS_HEADER))
			{
				Logger::error("[c_image] load: file too small");
				return false;
			}

			m_raw.resize(size);
			file.seekg(0, std::ios::beg);
			file.read(reinterpret_cast<char*>(m_raw.data()), static_cast<std::streamsize>(size));
			if (!file)
			{
				Logger::error("[c_image] load: failed to read file");
				return false;
			}

			const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(m_raw.data());
			if (dos->e_magic != IMAGE_DOS_SIGNATURE)
			{
				Logger::error("[c_image] load: invalid DOS signature");
				return false;
			}

			if (static_cast<std::size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > m_raw.size())
			{
				Logger::error("[c_image] load: invalid PE header offset");
				return false;
			}

			const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(m_raw.data() + dos->e_lfanew);
			if (nt->Signature != IMAGE_NT_SIGNATURE)
			{
				Logger::error("[c_image] load: invalid NT signature");
				return false;
			}

			m_is_64 = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
			if (m_is_64)
			{
				Logger::error("[c_image] load: x64 images are not supported yet (HydroThunder is x86)");
				return false;
			}

			m_image_base = nt->OptionalHeader.ImageBase;
			m_size_of_image = nt->OptionalHeader.SizeOfImage;
			m_entry_point = nt->OptionalHeader.AddressOfEntryPoint;

			const auto* section = IMAGE_FIRST_SECTION(nt);
			m_sections.clear();
			m_sections.reserve(nt->FileHeader.NumberOfSections);

			for (std::uint16_t i = 0; i < nt->FileHeader.NumberOfSections; ++i)
			{
				section_t s{};
				char name[9]{};
				std::memcpy(name, section[i].Name, 8);
				s.m_name = name;
				s.m_virtual_address = section[i].VirtualAddress;
				s.m_virtual_size = section[i].Misc.VirtualSize;
				s.m_raw_ptr = section[i].PointerToRawData;
				s.m_raw_size = section[i].SizeOfRawData;
				s.m_characteristics = section[i].Characteristics;
				m_sections.push_back(std::move(s));
			}

			m_mapped.assign(m_size_of_image, 0);
			const auto headers_size = (std::min)(
				static_cast<std::size_t>(nt->OptionalHeader.SizeOfHeaders),
				m_raw.size());
			std::memcpy(m_mapped.data(), m_raw.data(), headers_size);

			for (const auto& s : m_sections)
			{
				if (!s.m_raw_size || !s.m_raw_ptr)
					continue;

				const auto copy_size = (std::min)(
					static_cast<std::size_t>(s.m_raw_size),
					static_cast<std::size_t>(s.m_virtual_size ? s.m_virtual_size : s.m_raw_size));

				if (static_cast<std::size_t>(s.m_raw_ptr) + copy_size > m_raw.size())
					continue;
				if (static_cast<std::size_t>(s.m_virtual_address) + copy_size > m_mapped.size())
					continue;

				std::memcpy(
					m_mapped.data() + s.m_virtual_address,
					m_raw.data() + s.m_raw_ptr,
					copy_size);
			}

			Logger::print("[c_image] load: %s", path.string().c_str());
			Logger::print("[c_image] load: image_base=0x%08X size=0x%08X sections=%zu",
				m_image_base, m_size_of_image, m_sections.size());
			return true;
		}

		[[nodiscard]] bool is_valid() const noexcept
		{
			return !m_mapped.empty();
		}

		[[nodiscard]] bool is_64() const noexcept
		{
			return m_is_64;
		}

		[[nodiscard]] std::uint32_t image_base() const noexcept
		{
			return m_image_base;
		}

		[[nodiscard]] std::uint32_t size_of_image() const noexcept
		{
			return m_size_of_image;
		}

		[[nodiscard]] const std::filesystem::path& path() const noexcept
		{
			return m_path;
		}

		[[nodiscard]] const std::vector<section_t>& sections() const noexcept
		{
			return m_sections;
		}

		[[nodiscard]] bool contains_va(std::uint32_t va) const noexcept
		{
			return va >= m_image_base && (va - m_image_base) < m_size_of_image;
		}

		[[nodiscard]] bool contains_rva(std::uint32_t rva) const noexcept
		{
			return rva < m_size_of_image;
		}

		[[nodiscard]] std::uint32_t va_to_rva(std::uint32_t va) const noexcept
		{
			return va - m_image_base;
		}

		[[nodiscard]] std::uint32_t rva_to_va(std::uint32_t rva) const noexcept
		{
			return m_image_base + rva;
		}

		template<typename T>
		[[nodiscard]] T read_rva(std::uint32_t rva) const
		{
			T value{};
			if (!read_bytes_rva(rva, &value, sizeof(T)))
				return T{};
			return value;
		}

		template<typename T>
		[[nodiscard]] T read_va(std::uint32_t va) const
		{
			if (!contains_va(va))
				return T{};
			return read_rva<T>(va_to_rva(va));
		}

		[[nodiscard]] bool read_bytes_rva(std::uint32_t rva, void* out, std::size_t size) const
		{
			if (!out || !size)
				return false;
			if (static_cast<std::uint64_t>(rva) + size > m_mapped.size())
				return false;

			std::memcpy(out, m_mapped.data() + rva, size);
			return true;
		}

		[[nodiscard]] const std::uint8_t* data_rva(std::uint32_t rva) const noexcept
		{
			if (!contains_rva(rva))
				return nullptr;
			return m_mapped.data() + rva;
		}

		[[nodiscard]] std::string read_cstring_va(std::uint32_t va, std::size_t max_len = 512) const
		{
			if (!contains_va(va))
				return {};

			const auto* ptr = data_rva(va_to_rva(va));
			if (!ptr)
				return {};

			std::string out;
			out.reserve(64);
			for (std::size_t i = 0; i < max_len; ++i)
			{
				const char c = static_cast<char>(ptr[i]);
				if (c == '\0')
					break;
				if (c < 0x20 || c > 0x7E)
					return {};
				out.push_back(c);
			}
			return out;
		}

		[[nodiscard]] bool section_is_executable(std::uint32_t rva) const noexcept
		{
			for (const auto& s : m_sections)
			{
				const auto end = s.m_virtual_address + (std::max)(s.m_virtual_size, s.m_raw_size);
				if (rva >= s.m_virtual_address && rva < end)
					return (s.m_characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
			}
			return false;
		}

		[[nodiscard]] bool section_is_readable(std::uint32_t rva) const noexcept
		{
			for (const auto& s : m_sections)
			{
				const auto end = s.m_virtual_address + (std::max)(s.m_virtual_size, s.m_raw_size);
				if (rva >= s.m_virtual_address && rva < end)
					return (s.m_characteristics & IMAGE_SCN_MEM_READ) != 0;
			}
			return false;
		}

	private:
		std::filesystem::path m_path{};
		std::vector<std::uint8_t> m_raw{};
		std::vector<std::uint8_t> m_mapped{};
		std::vector<section_t> m_sections{};
		std::uint32_t m_image_base = 0;
		std::uint32_t m_size_of_image = 0;
		std::uint32_t m_entry_point = 0;
		bool m_is_64 = false;
	};
}
