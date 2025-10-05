#!/usr/bin/env python3
"""
Cyber Triage Tool - Main Entry Point
=====================================

A comprehensive cyber security incident response and forensics tool
with automated analysis and one-click investigation capabilities.
"""

import argparse
import logging
import sys
from pathlib import Path

from src.utils.logger import setup_logging
from src.utils.config import load_config
from src.triage_engine import TriageEngine


def main():
    """Main entry point for the cyber triage tool."""
    parser = argparse.ArgumentParser(
        description="Cyber Triage Tool - Automated Security Analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --quick-scan /path/to/evidence
  %(prog)s --full-analysis --target 192.168.1.100
  %(prog)s --investigate --case-id CASE-2024-001
  %(prog)s --web-interface
        """
    )
    
    # Analysis modes
    parser.add_argument(
        '--quick-scan', 
        metavar='PATH',
        help='Perform quick triage scan of specified path'
    )
    
    parser.add_argument(
        '--full-analysis', 
        action='store_true',
        help='Run comprehensive automated analysis'
    )
    
    parser.add_argument(
        '--investigate',
        action='store_true',
        help='Start interactive investigation mode'
    )
    
    # Target specification
    parser.add_argument(
        '--target',
        help='Target system IP address or hostname'
    )
    
    parser.add_argument(
        '--case-id',
        help='Case identifier for investigation tracking'
    )
    
    # Interface options
    parser.add_argument(
        '--web-interface',
        action='store_true',
        help='Start web-based interface'
    )
    
    parser.add_argument(
        '--cli-only',
        action='store_true',
        help='Force command-line interface only'
    )
    
    # Configuration
    parser.add_argument(
        '--config',
        default='config/default.yaml',
        help='Configuration file path'
    )
    
    parser.add_argument(
        '--output-dir',
        default='data/cases',
        help='Output directory for analysis results'
    )
    
    # Logging
    parser.add_argument(
        '--log-level',
        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
        default='INFO',
        help='Set logging level'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    log_level = 'DEBUG' if args.verbose else args.log_level
    setup_logging(log_level)
    logger = logging.getLogger(__name__)
    
    try:
        # Load configuration
        config = load_config(args.config)
        logger.info(f"Loaded configuration from {args.config}")
        
        # Initialize triage engine
        engine = TriageEngine(config, args.output_dir)
        logger.info("Cyber Triage Tool initialized")
        
        # Route to appropriate mode
        if args.quick_scan:
            logger.info(f"Starting quick scan of {args.quick_scan}")
            engine.quick_scan(args.quick_scan)
            
        elif args.full_analysis:
            if not args.target:
                logger.error("--target required for full analysis")
                return 1
            logger.info(f"Starting full analysis of {args.target}")
            engine.full_analysis(args.target, args.case_id)
            
        elif args.investigate:
            if not args.case_id:
                logger.error("--case-id required for investigation mode")
                return 1
            logger.info(f"Starting investigation for case {args.case_id}")
            engine.investigate(args.case_id)
            
        elif args.web_interface:
            logger.info("Starting web interface")
            engine.start_web_interface()
            
        else:
            # Default to interactive mode
            logger.info("Starting interactive mode")
            engine.interactive_mode()
            
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        return 0
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose:
            logger.exception("Full traceback:")
        return 1
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
