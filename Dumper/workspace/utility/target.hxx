#pragma once

namespace Dumper
{
	enum class target_id_t : std::uint8_t
	{
		unknown = 0,
		hydro_thunder
	};

	struct target_profile_t
	{
		target_id_t m_id = target_id_t::unknown;
		std::string m_name{ "generic" };
		std::string m_default_process{};
	};

	[[nodiscard]] inline const char* to_string(target_id_t id) noexcept
	{
		switch (id)
		{
		case target_id_t::hydro_thunder: return "hydro_thunder";
		default: return "unknown";
		}
	}

	[[nodiscard]] inline bool is_hydro_thunder(const target_profile_t& target) noexcept
	{
		return target.m_id == target_id_t::hydro_thunder;
	}

	// Detect target from image stem and/or live process name.
	[[nodiscard]] inline target_profile_t detect_target(
		const std::filesystem::path& image_path,
		std::string_view process_name = {})
	{
		target_profile_t out{};
		const auto stem = Common::to_lower(image_path.stem().string());
		const auto proc = Common::to_lower(std::string(process_name));
		const auto hay = stem + "|" + proc;

		if (hay.find("hydrothunder") != std::string::npos
			|| hay.find("hydro_thunder") != std::string::npos)
		{
			out.m_id = target_id_t::hydro_thunder;
			out.m_name = "HydroThunder";
			out.m_default_process = "HydroThunder.exe";
			return out;
		}

		out.m_name = image_path.stem().string().empty() ? "generic" : image_path.stem().string();
		if (!process_name.empty())
			out.m_default_process = std::string(process_name);
		return out;
	}
}
