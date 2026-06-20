"""
Command-line interface for IAM Policy Analyzer.
"""

import sys
from pathlib import Path
from typing import Optional, List
import json

import typer
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax
from tabulate import tabulate

from iam_policy_analyzer.analyzer import IAMAnalyzer
from iam_policy_analyzer.models import Severity

app = typer.Typer(
    name="iam-analyzer",
    help="Automated security analysis for IAM policies across cloud providers",
)
console = Console()


def print_banner():
    """Print the application banner."""
    banner = """
    ╔═══════════════════════════════════════════════════════╗
    ║   🔒 IAM Policy Analyzer                              ║
    ║   Automated security analysis for identity policies   ║
    ╚═══════════════════════════════════════════════════════╝
    """
    console.print(banner, style="cyan")


@app.command()
def analyze(
    policy_file: str = typer.Argument(
        ..., 
        help="Path to IAM policy file (JSON or YAML)"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--min-severity",
        "-s",
        help="Minimum severity to display (CRITICAL, HIGH, MEDIUM, LOW, INFO)"
    ),
    format_output: str = typer.Option(
        "table",
        "--format",
        "-f",
        help="Output format: table, json, csv"
    ),
    show_details: bool = typer.Option(
        False,
        "--details",
        "-d",
        help="Show detailed information for each finding"
    ),
):
    """
    Analyze an IAM policy file for security violations.
    
    Example:
        iam-analyzer analyze my-policy.json
        iam-analyzer analyze policy.yaml --min-severity HIGH
    """
    print_banner()
    
    # Validate file exists
    if not Path(policy_file).exists():
        console.print(f"[red]Error: Policy file not found: {policy_file}[/red]")
        raise typer.Exit(1)
    
    try:
        # Run analysis
        analyzer = IAMAnalyzer()
        console.print(f"[cyan]Analyzing: {policy_file}[/cyan]")
        
        result = analyzer.analyze_file(policy_file)
        
        # Filter by severity if specified
        findings = result.findings
        if severity:
            try:
                min_sev = Severity[severity.upper()]
                severity_order = {
                    Severity.CRITICAL: 4,
                    Severity.HIGH: 3,
                    Severity.MEDIUM: 2,
                    Severity.LOW: 1,
                    Severity.INFO: 0,
                }
                findings = [f for f in findings 
                          if severity_order[f.severity] >= severity_order[min_sev]]
            except KeyError:
                console.print(f"[red]Invalid severity: {severity}[/red]")
                raise typer.Exit(1)
        
        # Print summary
        console.print("\n[bold]📊 Analysis Summary[/bold]")
        summary_table = Table(show_header=False, box=None)
        summary_table.add_row("Total Findings", str(result.summary["total"]))
        summary_table.add_row("[bold red]CRITICAL[/bold red]", str(result.summary["critical"]))
        summary_table.add_row("[bold yellow]HIGH[/bold yellow]", str(result.summary["high"]))
        summary_table.add_row("[bold blue]MEDIUM[/bold blue]", str(result.summary["medium"]))
        summary_table.add_row("LOW", str(result.summary["low"]))
        summary_table.add_row("INFO", str(result.summary["info"]))
        
        console.print(summary_table)
        
        if not findings:
            console.print("\n[green]✓ No findings! Policy looks good.[/green]\n")
            raise typer.Exit(0)
        
        # Print findings
        console.print(f"\n[bold]🔍 Findings ({len(findings)})[/bold]\n")
        
        if format_output == "json":
            output = {
                "file": policy_file,
                "summary": result.summary,
                "findings": [
                    {
                        "check_id": f.check_id,
                        "check_name": f.check_name,
                        "severity": f.severity.value,
                        "message": f.message,
                        "affected_resource": f.affected_resource,
                        "remediation": f.remediation,
                        "details": f.details,
                    }
                    for f in findings
                ]
            }
            console.print(json.dumps(output, indent=2))
        
        elif format_output == "csv":
            rows = []
            for f in findings:
                rows.append([
                    f.check_id,
                    f.check_name,
                    f.severity.value,
                    f.affected_resource,
                    f.message,
                ])
            headers = ["Check ID", "Check Name", "Severity", "Resource", "Message"]
            console.print(tabulate(rows, headers=headers, tablefmt="grid"))
        
        else:  # table format
            for i, finding in enumerate(findings, 1):
                # Color code severity
                sev_color = {
                    Severity.CRITICAL: "red",
                    Severity.HIGH: "yellow",
                    Severity.MEDIUM: "blue",
                    Severity.LOW: "cyan",
                    Severity.INFO: "white",
                }[finding.severity]
                
                severity_str = f"[bold {sev_color}]{finding.severity.value}[/bold {sev_color}]"
                
                # Create panel for each finding
                content = f"""
[bold]ID:[/bold] {finding.check_id}
[bold]Name:[/bold] {finding.check_name}
[bold]Resource:[/bold] {finding.affected_resource}

[bold]Issue:[/bold]
{finding.message}

[bold]Remediation:[/bold]
{finding.remediation}
"""
                if finding.reference:
                    content += f"\n[bold]Reference:[/bold]\n{finding.reference}"
                
                if show_details and finding.details:
                    content += f"\n[bold]Details:[/bold]\n{json.dumps(finding.details, indent=2)}"
                
                panel = Panel(
                    content.strip(),
                    title=f"{i}. {severity_str}",
                    border_style=sev_color,
                    expand=False
                )
                console.print(panel)
        
        console.print(f"\n[cyan]✓ Analysis complete[/cyan]\n")
        
        # Exit with code based on critical findings
        if result.summary["critical"] > 0:
            raise typer.Exit(1)
        
    except Exception as e:
        console.print(f"[red]Error during analysis: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def batch(
    policy_dir: str = typer.Argument(
        ...,
        help="Directory containing policy files"
    ),
    output_file: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Write JSON results to file"
    ),
):
    """
    Analyze all policy files in a directory.
    
    Example:
        iam-analyzer batch ./policies/
        iam-analyzer batch ./policies/ --output results.json
    """
    print_banner()
    
    policy_dir_path = Path(policy_dir)
    if not policy_dir_path.is_dir():
        console.print(f"[red]Error: Not a directory: {policy_dir}[/red]")
        raise typer.Exit(1)
    
    # Find policy files
    policy_files = list(policy_dir_path.glob("**/*.json")) + \
                   list(policy_dir_path.glob("**/*.yaml")) + \
                   list(policy_dir_path.glob("**/*.yml"))
    
    if not policy_files:
        console.print(f"[yellow]No policy files found in {policy_dir}[/yellow]")
        raise typer.Exit(0)
    
    console.print(f"[cyan]Found {len(policy_files)} policy files[/cyan]\n")
    
    analyzer = IAMAnalyzer()
    results = {}
    
    for policy_file in policy_files:
        try:
            rel_path = policy_file.relative_to(policy_dir_path)
            console.print(f"[cyan]Analyzing: {rel_path}[/cyan]")
            result = analyzer.analyze_file(str(policy_file))
            results[str(rel_path)] = result
        except Exception as e:
            console.print(f"[yellow]Error analyzing {policy_file}: {e}[/yellow]")
    
    # Print summary
    total_findings = sum(len(r.findings) for r in results.values())
    console.print(f"\n[bold]📊 Batch Analysis Summary[/bold]")
    console.print(f"Files analyzed: {len(results)}")
    console.print(f"Total findings: {total_findings}")
    
    # Output to file if requested
    if output_file:
        output_data = {
            "files": len(results),
            "total_findings": total_findings,
            "results": {
                file: {
                    "summary": result.summary,
                    "findings": [
                        {
                            "check_id": f.check_id,
                            "severity": f.severity.value,
                            "message": f.message,
                        }
                        for f in result.findings
                    ]
                }
                for file, result in results.items()
            }
        }
        
        with open(output_file, "w") as f:
            json.dump(output_data, f, indent=2)
        
        console.print(f"\n[green]✓ Results saved to {output_file}[/green]")


@app.command()
def version():
    """Show version information."""
    console.print("IAM Policy Analyzer v0.1.0")
    console.print("https://github.com/xamitgupta/iam-policy-analyzer")


def main():
    """Main entry point."""
    app()


if __name__ == "__main__":
    main()
