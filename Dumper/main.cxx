#include <impl/includes.hxx>

namespace
{
	[[nodiscard]] bool looks_like_process_name(const std::string& arg)
	{
		if (arg.empty() || arg[0] == '-')
			return false;
		if (arg.find('\\') != std::string::npos || arg.find('/') != std::string::npos)
			return false;
		if (arg.size() >= 2 && arg[1] == ':')
			return false;

		const auto dot = arg.find_last_of('.');
		if (dot == std::string::npos)
			return true;

		auto ext = arg.substr(dot);
		for (char& c : ext)
			c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
		return ext == ".exe" || ext == ".dll";
	}
}

int main(int argc, char** argv)
{
	Logger::print_watermark();

	std::filesystem::path input_path;
	std::filesystem::path output_path;
	bool live = false;
	std::string live_process{};
	std::vector<std::string> positionals;

	for (int i = 1; i < argc; ++i)
	{
		const std::string arg = argv[i];
		if (arg == "--live")
		{
			live = true;
			if (i + 1 < argc && looks_like_process_name(argv[i + 1]))
				live_process = argv[++i];
			continue;
		}

		if (arg == "--help" || arg == "-h")
		{
			Logger::print("usage:");
			Logger::print("  Dumper.exe --live [ProcessName.exe] [out_dir]");
			Logger::print("  Dumper.exe <exe_path> [out_dir]");
			Logger::print("  Dumper.exe <exe_path> [out_dir] --live [ProcessName.exe]");
			Logger::print("notes:");
			Logger::print("  Target profile is auto-detected from the image/process name.");
			Logger::print("  HydroThunder-specific layouts only apply when that target is detected.");
			return 0;
		}

		positionals.push_back(arg);
	}

	if (live)
	{
		if (live_process.empty())
			live_process = "HydroThunder.exe"; // fallback only when --live has no name

		c_live_enricher::attach_info_t attach{};
		if (!c_live_enricher::resolve_running_image(live_process, attach))
		{
			Logger::error("[c_main] main: failed to attach / resolve image from running process");
			return 1;
		}

		input_path = attach.m_image_path;
		for (const auto& p : positionals)
		{
			const std::filesystem::path candidate = p;
			const auto ext = candidate.extension().string();
			std::string ext_l = ext;
			for (char& c : ext_l)
				c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

			// Ignore leftover "<exe>" positionals from older CLI habits; image comes from the process.
			if (ext_l == ".exe" && std::filesystem::is_regular_file(candidate))
				continue;

			output_path = candidate;
			break;
		}
	}
	else
	{
		if (positionals.empty())
		{
			Logger::error("[c_main] main: missing exe path (or pass --live to attach to a running process)");
			Logger::print("usage: Dumper.exe --live [ProcessName.exe] [out_dir]");
			return 1;
		}

		input_path = positionals[0];
		if (positionals.size() >= 2)
			output_path = positionals[1];
	}

	Logger::print("[c_main] main: starting hybrid dump (live=%s process=%s)",
		live ? "true" : "false", live_process.c_str());
	Logger::print("[c_main] main: image=%s", input_path.string().c_str());

	c_dumper dumper{};
	if (!dumper.run(input_path, output_path, live, live_process))
	{
		Logger::error("[c_main] main: dump failed");
		return 1;
	}

	Logger::print("[c_main] main: dump succeeded");
	return 0;
}
