import argparse
import yaml


def main():
    print(f"[Trace Guided Analysis] Just started!")  
    parser = argparse.ArgumentParser(description="Entry point generation")
    parser.add_argument('config_path', help="Config file for entry point generation.")
    args = parser.parse_args()
    from .trace_guided_analysis import find_entry_points_with_config
    find_entry_points_with_config(args.config_path)

if __name__ == '__main__':
    main()
