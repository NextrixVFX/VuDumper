#pragma once

namespace Dumper
{
	class c_dumper
	{
	public:
		[[nodiscard]] bool run(
			const std::filesystem::path& input_path,
			std::filesystem::path output_dir = {},
			bool live = false,
			std::string live_process = {})
		{
			Logger::print("[c_dumper] run: input=%s", input_path.string().c_str());

			if (!std::filesystem::exists(input_path))
			{
				Logger::error("[c_dumper] run: input path does not exist");
				return false;
			}

			Pe::c_image image{};
			if (!image.load(input_path))
				return false;

			Types::dump_result_t result{};
			result.m_image_base = image.image_base();
			result.m_target = detect_target(input_path, live_process);
			if (live_process.empty() && !result.m_target.m_default_process.empty())
				live_process = result.m_target.m_default_process;

			Logger::print("[c_dumper] run: target=%s (%s)",
				result.m_target.m_name.c_str(), to_string(result.m_target.m_id));

			c_rtti_scanner rtti{};
			if (!rtti.scan(image, result))
				Logger::warn("[c_dumper] run: rtti scan produced no classes");

			c_property_scanner props{};
			if (!props.scan(image, result))
				Logger::warn("[c_dumper] run: property scan produced no members");

			c_globals_scanner globals{};
			if (!globals.scan(image, result))
				Logger::warn("[c_dumper] run: globals scan produced no singletons");

			c_engine_model::apply(result);

			result.m_property_count = 0;
			for (const auto& c : result.m_classes)
				result.m_property_count += c.m_properties.size();

			if (output_dir.empty())
				output_dir = Common::make_output_dir(input_path);

			// Verify the chosen directory is actually writable.
			{
				std::error_code ec;
				std::filesystem::create_directories(output_dir, ec);
				const auto probe = output_dir / ".vu_write_probe";
				std::ofstream test(probe);
				if (!test)
				{
					const auto fallback = Common::cwd_output_dir(input_path);
					Logger::warn("[c_dumper] run: output dir not writable, using cwd fallback");
					output_dir = fallback;
					ec.clear();
					std::filesystem::create_directories(output_dir, ec);
					if (ec)
					{
						Logger::error("[c_dumper] run: failed to create output directory");
						return false;
					}
				}
				else
				{
					test.close();
					std::filesystem::remove(probe, ec);
				}
			}

			c_sdk_emitter emitter{};
			if (!emitter.emit(result, output_dir))
			{
				Logger::error("[c_dumper] run: failed to emit sdk");
				return false;
			}

			if (live)
			{
				if (live_process.empty())
				{
					Logger::warn("[c_dumper] run: --live requested but no process name (pass ProcessName.exe)");
				}
				else
				{
					c_live_enricher enricher{};
					if (enricher.enrich(result, output_dir, live_process))
					{
						c_engine_model::rebuild_from_discovered(result);

						result.m_property_count = 0;
						for (const auto& c : result.m_classes)
							result.m_property_count += c.m_properties.size();

						if (!emitter.emit(result, output_dir))
						{
							Logger::error("[c_dumper] run: failed to re-emit sdk after live enrich");
							return false;
						}
					}
				}
			}

			Logger::print("[c_dumper] run: done (rtti=%zu props=%zu globals=%zu)",
				result.m_rtti_count, result.m_property_count, result.m_globals.size());
			Logger::print("[c_dumper] run: output=%s", output_dir.string().c_str());
			return true;
		}
	};
}
