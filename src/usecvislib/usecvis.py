#
# VULNEX -Universal Security Visualization Library-
#
# File: usecvis.py
# Author: Simon Roses Femerling
# Created: 2025-01-01
# Last Modified: 2025-12-23
# Version: 0.3.1
# License: Apache-2.0
# Copyright (c) 2025 VULNEX. All rights reserved.
# https://www.vulnex.com
#

"""Universal Security Visualization Library CLI.

Command-line interface for generating security visualizations including
attack trees, threat models, and binary analysis diagrams.

Supports TOML, JSON, and YAML input formats for attack trees and threat models.
"""

import getopt
import os
import sys
from typing import NoReturn, Optional


def Usage() -> None:
    """Display usage information."""
    print("USecVisLib - Universal Security Visualization Library")
    print("")
    print("Usage: usecvis [options]")
    print("")
    print("Options:")
    print("  -h, --help              Show this help message")
    print("  -i, --ifile <file>      Input file (required)")
    print("                          Supports: .toml, .tml, .json, .yaml, .yml, .mmd")
    print("  -o, --ofile <file>      Output file (required)")
    print("  -f, --format <format>   Output format: png, pdf, svg, dot (default: png)")
    print("  -m, --mode <mode>       Visualization mode:")
    print("                            0 - Attack Trees (default)")
    print("                            1 - Threat Modeling")
    print("                            2 - Binary Visualization")
    print("                            3 - Attack Graphs")
    print("                            4 - Mermaid Diagrams")
    print("                            5 - Cloud Diagrams")
    print("                            6 - Privilege Gradient Graphs")
    print("                            7 - Component Diagrams")
    print("                            8 - Dependency Graphs")
    print("  -s, --styleid <id>      Style ID (per mode):")
    print("                          Attack Trees (mode 0):")
    print("                            at_default, at_corporate, at_neon, at_pastel,")
    print("                            at_forest, at_fire, at_blueprint, at_sunset,")
    print("                            at_hacker, at_minimal, at_plain,")
    print("                            at_white_black, at_black_white,")
    print("                            at_nordic, at_amethyst, at_steel,")
    print("                            at_glacier, at_terra")
    print("                          Attack Graphs (mode 3):")
    print("                            ag_default, ag_dark, ag_security, ag_network,")
    print("                            ag_minimal, ag_neon, ag_corporate, ag_hacker,")
    print("                            ag_blueprint, ag_plain,")
    print("                            ag_nordic, ag_amethyst, ag_steel,")
    print("                            ag_glacier, ag_terra, ag_doc_light")
    print("                          Threat Modeling (mode 1):")
    print("                            tm_default, tm_stride, tm_dark, tm_corporate,")
    print("                            tm_neon, tm_minimal, tm_ocean, tm_sunset,")
    print("                            tm_forest, tm_blueprint, tm_hacker, tm_plain,")
    print("                            tm_doc_light, tm_doc_clean")
    print("                          Privilege Gradient Graphs (mode 6):")
    print("                            pg_default, pg_dark, pg_security, pg_neon,")
    print("                            pg_corporate")
    print("                          Component Diagrams (mode 7):")
    print("                            cd_default, cd_blueprint, cd_minimal, cd_dark")
    print("                          Dependency Graphs (mode 8):")
    print("                            dg_default, dg_dark, dg_minimal, dg_coupling")
    print("                          Binary Visualization (mode 2):")
    print("                            bv_default, bv_dark, bv_security, bv_ocean,")
    print("                            bv_forest, bv_sunset, bv_cyber, bv_minimal,")
    print("                            bv_corporate, bv_fire, bv_purple, bv_rainbow")
    print("  -S, --stylefile <file>  Custom style file path")
    print("  -v, --visualization     Visualization type for binary mode:")
    print("                            all, entropy, distribution, windrose, heatmap")
    print("  -C, --config <file>     Configuration file for binary visualization parameters")
    print("                          (TOML format, controls entropy/distribution/windrose/heatmap settings)")
    print("  -r, --report            Generate STRIDE report (threat modeling only)")
    print("  -p, --paths <src,tgt>   Find attack paths between nodes (attack graphs)")
    print("  -c, --critical          Analyze critical nodes (attack graphs)")
    print("  -t, --theme <theme>     Mermaid theme: default, dark, forest, neutral, base")
    print("  -d, --direction <dir>   Cloud diagram direction: TB, BT, LR, RL")
    print("")
    print("  --convert <format>      Convert input file to format: toml, json, yaml, mermaid")
    print("                          Output will be saved to <output>.<format_ext>")
    print("                          Mermaid output auto-detects visualization type")
    print("")
    print("Examples:")
    print("  usecvis -i attack.toml -o output -m 0")
    print("  usecvis -i attack.json -o output -m 0")
    print("  usecvis -i threat.yaml -o diagram -m 1 -s tm_stride")
    print("  usecvis -i binary.exe -o analysis -m 2 -v entropy")
    print("  usecvis -i binary.exe -o analysis -m 2 -C binvis_config.toml")
    print("  usecvis -i network.toml -o graph -m 3 -s ag_security")
    print("  usecvis -i network.toml -o graph -m 3 -p attacker,database -c")
    print("  usecvis -i diagram.mmd -o output -m 4 -t dark")
    print("  usecvis -i cloud.toml -o architecture -m 5 -d LR")
    print("")
    print("Format Conversion Examples:")
    print("  usecvis -i attack.toml -o attack --convert json")
    print("  usecvis -i threat.yaml -o threat --convert toml")
    print("  usecvis -i attack.toml -o diagram --convert mermaid")
    print("")


def validate_format(format: str) -> bool:
    """Validate output format.

    Args:
        format: The format string to validate.

    Returns:
        True if format is valid, False otherwise.
    """
    return format in ['png', 'pdf', 'svg', 'dot']


def validate_mode(mode: int) -> bool:
    """Validate visualization mode.

    Args:
        mode: The mode integer to validate.

    Returns:
        True if mode is valid, False otherwise.
    """
    return mode in [0, 1, 2, 3, 4, 5, 6, 7, 8]


def error_exit(message: str, show_usage: bool = True) -> NoReturn:
    """Print error message and exit.

    Args:
        message: Error message to display.
        show_usage: Whether to show usage information.
    """
    print(f"Error: {message}", file=sys.stderr)
    if show_usage:
        print("")
        Usage()
    sys.exit(2)


def main(argv: Optional[list[str]] = None) -> int:
    """Main entry point for the CLI.

    Args:
        argv: Command line arguments. Uses sys.argv[1:] if None.

    Returns:
        Exit code (0 for success, non-zero for errors).
    """
    if argv is None:
        argv = sys.argv[1:]

    inputfile = ''
    outputfile = ''
    format = 'png'
    mode = 0
    styleid = ""
    visualization = "all"
    configfile = ""  # Configuration file for binary visualization parameters
    generate_report = False
    attack_paths = ""  # source,target for attack graph path analysis
    analyze_critical = False
    theme = "default"  # Mermaid theme
    direction = "TB"   # Cloud diagram direction

    convert_format = ""  # Format to convert to: toml, json, yaml, mermaid

    try:
        opts, args = getopt.getopt(
            argv,
            "hi:o:f:m:s:S:v:C:rp:ct:d:",
            ["help", "ifile=", "ofile=", "format=", "mode=", "styleid=",
             "stylefile=", "visualization=", "config=", "report", "paths=", "critical",
             "convert=", "theme=", "direction="]
        )
    except getopt.GetoptError as e:
        error_exit(str(e))

    for opt, arg in opts:
        if opt in ('-h', '--help'):
            Usage()
            return 0
        elif opt in ("-i", "--ifile"):
            inputfile = arg
        elif opt in ("-o", "--ofile"):
            outputfile = arg
        elif opt in ("-f", "--format"):
            format = arg
        elif opt in ("-m", "--mode"):
            try:
                mode = int(arg)
            except ValueError:
                error_exit(f"Invalid mode: {arg}. Must be 0-8.")
        elif opt in ("-s", "--styleid"):
            styleid = arg
        elif opt in ("-S", "--stylefile"):
            pass
        elif opt in ("-v", "--visualization"):
            visualization = arg
        elif opt in ("-C", "--config"):
            configfile = arg
        elif opt in ("-r", "--report"):
            generate_report = True
        elif opt in ("-p", "--paths"):
            attack_paths = arg
        elif opt in ("-c", "--critical"):
            analyze_critical = True
        elif opt in ("-t", "--theme"):
            theme = arg
        elif opt in ("-d", "--direction"):
            direction = arg.upper()
        elif opt == "--convert":
            convert_format = arg.lower()

    # Handle format conversion mode
    if convert_format:
        if not inputfile:
            error_exit("Input file is required for conversion. Use -i <file>")
        if not outputfile:
            error_exit("Output file is required for conversion. Use -o <file>")
        if not os.path.isfile(inputfile):
            error_exit(f"Input file not found: {inputfile}", show_usage=False)

        valid_convert_formats = ['toml', 'json', 'yaml', 'mermaid']
        if convert_format not in valid_convert_formats:
            error_exit(f"Invalid convert format: {convert_format}. Must be one of: {', '.join(valid_convert_formats)}")

        try:
            from .mermaid import detect_visualization_type, serialize_to_mermaid
            from .utils import convert_format as do_convert

            # Determine input format from file extension
            input_ext = os.path.splitext(inputfile)[1].lower()
            input_format_map = {
                '.toml': 'toml', '.tml': 'toml',
                '.json': 'json',
                '.yaml': 'yaml', '.yml': 'yaml'
            }

            if input_ext not in input_format_map:
                error_exit(f"Unsupported input file format: {input_ext}. Must be .toml, .tml, .json, .yaml, or .yml")

            input_format = input_format_map[input_ext]

            # Determine output extension
            output_ext_map = {
                'toml': '.toml',
                'json': '.json',
                'yaml': '.yaml',
                'mermaid': '.mmd'
            }
            output_ext = output_ext_map[convert_format]
            output_path = f"{outputfile}{output_ext}"

            if convert_format == 'mermaid':
                # Special handling for Mermaid - need to parse and convert
                import json

                import toml
                import yaml as yaml_lib

                # Parse input file
                with open(inputfile, encoding='utf-8') as f:
                    content = f.read()

                if input_format == 'toml':
                    data = toml.loads(content)
                elif input_format == 'json':
                    data = json.loads(content)
                else:  # yaml
                    data = yaml_lib.safe_load(content)

                # Detect visualization type and convert to Mermaid
                vis_type = detect_visualization_type(data)
                mermaid_output = serialize_to_mermaid(data, diagram_type=vis_type)

                # Write output
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(mermaid_output)

                print(f"Converted {inputfile} to Mermaid format: {output_path}")
                print(f"Detected visualization type: {vis_type}")
            else:
                # Standard format conversion (toml, json, yaml)
                do_convert(inputfile, output_path, convert_format)
                print(f"Converted {inputfile} to {convert_format.upper()}: {output_path}")

            return 0

        except Exception as e:
            error_exit(f"Conversion failed: {e}", show_usage=False)

    # Validate required arguments
    if not inputfile:
        error_exit("Input file is required. Use -i <file>")

    if not outputfile:
        error_exit("Output file is required. Use -o <file>")

    # Validate input file exists (except for binary mode which handles it)
    if mode != 2 and not os.path.isfile(inputfile):
        error_exit(f"Input file not found: {inputfile}", show_usage=False)

    # Validate format
    if not validate_format(format):
        error_exit(f"Invalid format: {format}. Must be png, pdf, svg, or dot.")

    # Validate mode
    if not validate_mode(mode):
        error_exit(f"Invalid mode: {mode}. Must be 0-8.")

    # Execute based on mode
    try:
        if mode == 0:
            # Attack Trees
            from . import attacktrees
            at = attacktrees.AttackTrees(inputfile, outputfile, format, styleid)
            at.BuildAttackTree()
            print(f"Attack tree generated: {outputfile}.{format}")

        elif mode == 1:
            # Threat Modeling
            from . import threatmodeling
            tm = threatmodeling.ThreatModeling(inputfile, outputfile, format, styleid)
            tm.BuildThreatModel()
            print(f"Threat model generated: {outputfile}.{format}")

            if generate_report:
                report_file = f"{outputfile}_stride_report.md"
                tm.generate_stride_report(report_file)
                print(f"STRIDE report generated: {report_file}")

        elif mode == 2:
            # Binary Visualization
            if not os.path.isfile(inputfile):
                error_exit(f"Input file not found: {inputfile}", show_usage=False)

            # Validate config file if provided
            if configfile and not os.path.isfile(configfile):
                error_exit(f"Config file not found: {configfile}", show_usage=False)

            from . import binvis
            bv = binvis.BinVis(inputfile, outputfile, format, styleid, configfile)

            # Validate visualization type
            valid_vis = ['all', 'entropy', 'distribution', 'windrose', 'heatmap']
            if visualization not in valid_vis:
                error_exit(f"Invalid visualization: {visualization}. Must be one of: {', '.join(valid_vis)}")

            bv.BuildBinVis(visualization)

            if visualization == 'all':
                print(f"Binary visualizations generated: {outputfile}_*.{format}")
            else:
                print(f"Binary visualization generated: {outputfile}_{visualization}.{format}")

            # Print file stats
            stats = bv.get_file_stats()
            print("\nFile Statistics:")
            print(f"  Size: {stats['file_size']:,} bytes")
            print(f"  Entropy: {stats['entropy']:.4f} bits")
            print(f"  Unique bytes: {stats['unique_bytes']}/256")
            print(f"  Null bytes: {stats['null_percentage']:.2f}%")
            print(f"  Printable ASCII: {stats['printable_percentage']:.2f}%")

        elif mode == 3:
            # Attack Graphs
            from . import attackgraphs
            ag = attackgraphs.AttackGraphs(inputfile, outputfile, format, styleid)
            ag.BuildAttackGraph()
            print(f"Attack graph generated: {outputfile}.{format}")

            # Print graph statistics
            stats = ag.get_graph_stats()
            print("\nGraph Statistics:")
            print(f"  Name: {stats['name']}")
            print(f"  Hosts: {stats['total_hosts']}")
            print(f"  Vulnerabilities: {stats['total_vulnerabilities']}")
            print(f"  Privileges: {stats['total_privileges']}")
            print(f"  Services: {stats['total_services']}")
            print(f"  Exploits: {stats['total_exploits']}")
            print(f"  Total nodes: {stats['total_nodes']}")
            print(f"  Total edges: {stats['total_edges']}")
            if stats['total_vulnerabilities'] > 0:
                print(f"  Average CVSS: {stats['average_cvss']:.1f}")
                print(f"  Critical vulns (CVSS >= 9.0): {stats['critical_vulnerabilities']}")

            # Analyze attack paths if requested
            if attack_paths:
                parts = attack_paths.split(',')
                if len(parts) != 2:
                    error_exit("Attack paths must be in format: source,target")
                source, target = parts[0].strip(), parts[1].strip()
                paths = ag.find_attack_paths(source, target)
                if paths:
                    print(f"\nAttack Paths from '{source}' to '{target}':")
                    for i, path in enumerate(paths[:10], 1):  # Show top 10
                        print(f"  {i}. {' -> '.join(path)} (length: {len(path)})")
                    if len(paths) > 10:
                        print(f"  ... and {len(paths) - 10} more paths")
                    shortest = ag.shortest_path(source, target)
                    if shortest:
                        print(f"\n  Shortest path length: {len(shortest)}")
                else:
                    print(f"\nNo paths found from '{source}' to '{target}'")

            # Analyze critical nodes if requested
            if analyze_critical:
                critical = ag.analyze_critical_nodes(top_n=10)
                if critical:
                    print("\nTop Critical Nodes (by degree centrality):")
                    for i, node in enumerate(critical, 1):
                        print(f"  {i}. {node['label']} ({node['type']})")
                        print(f"     In-degree: {node['in_degree']}, Out-degree: {node['out_degree']}")
                        print(f"     Criticality score: {node['criticality_score']}")

        elif mode == 4:
            # Mermaid Diagrams
            from . import mermaiddiagrams

            # Validate theme
            valid_themes = ['default', 'dark', 'forest', 'neutral', 'base']
            if theme not in valid_themes:
                error_exit(f"Invalid theme: {theme}. Must be one of: {', '.join(valid_themes)}")

            # Validate format for Mermaid
            valid_mermaid_formats = ['png', 'svg', 'pdf']
            if format not in valid_mermaid_formats:
                error_exit(f"Invalid format for Mermaid: {format}. Must be one of: {', '.join(valid_mermaid_formats)}")

            md = mermaiddiagrams.MermaidDiagrams(theme=theme, validate_cli=True)
            md.load(inputfile)
            result = md.render(outputfile, format=format)
            print(f"Mermaid diagram generated: {result.output_path}")

            # Print diagram statistics
            stats = md.get_stats()
            print("\nDiagram Statistics:")
            print(f"  Type: {stats['diagram_type']}")
            print(f"  Lines: {stats['line_count']}")
            print(f"  Characters: {stats['char_count']}")

        elif mode == 5:
            # Cloud Diagrams
            from . import clouddiagrams

            # Validate direction
            valid_directions = ['TB', 'BT', 'LR', 'RL']
            if direction not in valid_directions:
                error_exit(f"Invalid direction: {direction}. Must be one of: {', '.join(valid_directions)}")

            # Validate format for Cloud diagrams
            valid_cloud_formats = ['png', 'jpg', 'svg', 'pdf', 'dot']
            if format not in valid_cloud_formats:
                error_exit(f"Invalid format for Cloud: {format}. Must be one of: {', '.join(valid_cloud_formats)}")

            cd = clouddiagrams.CloudDiagrams(direction=direction, show=False)
            cd.load(inputfile)
            result = cd.render(outputfile, format=format)
            print(f"Cloud diagram generated: {result.output_path}")

            # Print diagram statistics
            stats = cd.get_stats()
            print("\nDiagram Statistics:")
            print(f"  Title: {stats['title']}")
            print(f"  Nodes: {stats['node_count']}")
            print(f"  Edges: {stats['edge_count']}")
            print(f"  Clusters: {stats['cluster_count']}")
            if stats['providers_used']:
                print(f"  Providers: {', '.join(stats['providers_used'])}")

        elif mode == 6:
            # Privilege Gradient Graphs
            from . import privilegegradient
            pg = privilegegradient.PrivilegeGradient(inputfile, outputfile, format, styleid)
            pg.BuildPrivilegeGradient()
            print(f"Privilege gradient graph generated: {outputfile}.{format}")

            # Print stats
            stats = pg.get_stats()
            print("\nGradient Statistics:")
            print(f"  Name: {stats['name']}")
            print(f"  Zones: {stats['total_zones']}")
            print(f"  Components: {stats['total_components']}")
            print(f"  Influences: {stats['total_influences']}")
            print(f"  Inversions: {stats['total_inversions']}")
            if stats['max_trust_gap'] > 0:
                print(f"  Max trust gap: {stats['max_trust_gap']}")

            # Print inversions
            if stats['total_inversions'] > 0:
                print("\nDetected Inversions:")
                for inv in stats['inversions']:
                    print(f"  [{inv['severity'].upper()}] {inv['from']} ({inv['from_zone']}) "
                          f"-> {inv['to']} ({inv['to_zone']}) "
                          f"[gap={inv['trust_gap']}]")

        elif mode == 7:
            # Component Diagrams
            from . import componentdiagram
            cd = componentdiagram.ComponentDiagram(inputfile, outputfile, format, styleid)
            cd.BuildComponentDiagram()
            print(f"Component diagram generated: {outputfile}.{format}")

            stats = cd.get_stats()
            print("\nDiagram Statistics:")
            print(f"  Title: {stats['title']}")
            print(f"  Layers: {stats['total_layers']}")
            print(f"  Components: {stats['total_components']}")
            print(f"  Connections: {stats['total_connections']}")

        elif mode == 8:
            # Dependency Graphs
            from . import dependencygraph
            dg = dependencygraph.DependencyGraph(inputfile, outputfile, format, styleid)
            dg.BuildDependencyGraph()
            print(f"Dependency graph generated: {outputfile}.{format}")

            stats = dg.get_stats()
            print("\nGraph Statistics:")
            print(f"  Title: {stats['title']}")
            print(f"  Modules: {stats['total_modules']}")
            print(f"  Dependencies: {stats['total_dependencies']}")
            print(f"  Circular: {stats['total_circular']}")
            print(f"  Internal: {stats['internal_count']}")
            print(f"  External: {stats['external_count']}")
            if stats['groups']:
                print(f"  Groups: {', '.join(stats['groups'])}")

    except FileNotFoundError as e:
        error_exit(str(e), show_usage=False)
    except Exception as e:
        error_exit(f"Visualization failed: {e}", show_usage=False)

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
