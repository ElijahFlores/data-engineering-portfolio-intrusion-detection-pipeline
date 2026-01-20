"""
MAIN PIPELINE: Intrusion Detection ETL System
Orchestrates Extract, Transform, Load, and Anomaly Detection

Fixed:
- Proper package imports
- Division by zero protection
- Empty DataFrame validation
- Actual performance benchmarking
- Error recovery

Usage:
    python main_pipeline.py
"""
import sys
import time
from pathlib import Path
from datetime import datetime

# FIXED: Add src directory to path for imports
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from src.extract import LogExtractor
from src.transform import LogTransformer
from src.load import DataLoader
from src.detect_anomalies import IntrusionDetector

class IntrusionDetectionPipeline:
    """Main ETL pipeline for intrusion detection"""
    
    def __init__(self, 
                 input_dir: str = 'data/raw',
                 output_dir: str = 'output/processed'):
        """
        Initialize pipeline components
        
        Args:
            input_dir: Directory containing raw log files
            output_dir: Directory for processed output
        """
        self.input_dir = input_dir
        self.output_dir = output_dir
        
        # Initialize components
        self.extractor = LogExtractor(input_dir)
        self.transformer = LogTransformer()
        self.loader = DataLoader(output_dir)
        self.detector = IntrusionDetector(
            brute_force_threshold=10,
            time_window_minutes=60
        )
        
        self.start_time = None
        self.end_time = None
        self.metrics = {}
    
    def run(self, log_filename: str = 'ssh_auth.log') -> dict:
        """
        Execute the complete ETL pipeline
        
        Pipeline Steps:
        1. EXTRACT: Read raw log files
        2. TRANSFORM: Parse and structure data
        3. LOAD: Store processed data
        4. DETECT: Identify anomalies and threats
        
        Returns:
            Dictionary with results and metrics
        """
        self.start_time = time.time()
        start_datetime = datetime.now()
        
        print("\n" + "="*70)
        print("INTRUSION DETECTION ETL PIPELINE")
        print(f"Started at: {start_datetime.strftime('%Y-%m-%d %H:%M:%S')}")
        print("="*70 + "\n")
        
        try:
            # STEP 1: EXTRACT
            print("STEP 1: EXTRACTING LOG DATA")
            print("-" * 70)
            extract_start = time.time()
            
            raw_logs = self.extractor.extract_logs(log_filename)
            
            extract_time = time.time() - extract_start
            self.metrics['extract_time'] = extract_time
            self.metrics['raw_log_count'] = len(raw_logs)
            print(f"⏱  Extract time: {extract_time:.2f}s\n")
            
            # STEP 2: TRANSFORM
            print("STEP 2: TRANSFORMING LOG DATA")
            print("-" * 70)
            transform_start = time.time()
            
            processed_df = self.transformer.transform_logs(raw_logs)
            
            transform_time = time.time() - transform_start
            self.metrics['transform_time'] = transform_time
            self.metrics['parsed_count'] = len(processed_df)
            self.metrics['parse_success_rate'] = (
                len(processed_df) / len(raw_logs) * 100 if raw_logs else 0
            )
            
            print(f"⏱  Transform time: {transform_time:.2f}s\n")
            
            # FIXED: Validate we have data before proceeding
            if processed_df.empty:
                raise ValueError(
                    "No logs were successfully parsed. Check log format and transformer regex."
                )
            
            # STEP 3: LOAD
            print("STEP 3: LOADING PROCESSED DATA")
            print("-" * 70)
            load_start = time.time()
            
            csv_path = self.loader.load_to_csv(processed_df, 'processed_logs.csv')
            
            # Generate and save summary stats
            summary_stats = self.loader.create_summary_stats(processed_df)
            summary_path = self.loader.load_to_csv(summary_stats, 'summary_stats.csv')
            
            # Try Parquet (optional)
            try:
                parquet_path = self.loader.load_to_parquet(processed_df, 'processed_logs.parquet')
                self.metrics['parquet_saved'] = True
            except Exception as e:
                print(f"  ℹ  Parquet save skipped: {e}")
                self.metrics['parquet_saved'] = False
            
            load_time = time.time() - load_start
            self.metrics['load_time'] = load_time
            print(f"⏱  Load time: {load_time:.2f}s\n")
            
            # STEP 4: DETECT ANOMALIES
            print("STEP 4: DETECTING ANOMALIES")
            print("-" * 70)
            detect_start = time.time()
            
            anomaly_report = self.detector.generate_full_report(processed_df)
            
            # Save anomaly reports
            saved_anomalies = self.loader.load_anomalies(anomaly_report)
            
            detect_time = time.time() - detect_start
            self.metrics['detect_time'] = detect_time
            self.metrics['anomalies_found'] = anomaly_report['summary']['total_anomalies']
            self.metrics['critical_threats'] = anomaly_report['summary']['critical_threats']
            print(f"⏱  Detection time: {detect_time:.2f}s\n")
            
            # COMPLETION METRICS
            self.end_time = time.time()
            total_duration = self.end_time - self.start_time
            
            # FIXED: Safe processing rate calculation
            processing_rate = (
                len(processed_df) / total_duration if total_duration > 0 else 0
            )
            
            self.metrics['total_duration'] = total_duration
            self.metrics['processing_rate'] = processing_rate
            
            print("\n" + "="*70)
            print("✅ PIPELINE COMPLETED SUCCESSFULLY")
            print("="*70)
            print(f"Completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Total duration: {total_duration:.2f} seconds")
            print(f"Records processed: {len(processed_df):,}")
            print(f"Processing rate: {processing_rate:.0f} records/second")
            print(f"Parse success rate: {self.metrics['parse_success_rate']:.1f}%")
            print("="*70 + "\n")
            
            print("📁 OUTPUT FILES:")
            print(f"  ✓ Processed logs: {csv_path}")
            print(f"  ✓ Summary stats: {summary_path}")
            
            for anomaly_type, filepath in saved_anomalies.items():
                anomaly_name = anomaly_type.replace('_', ' ').title()
                print(f"  ✓ {anomaly_name}: {filepath}")
            
            print("\n" + "="*70)
            print("📊 PERFORMANCE METRICS")
            print("="*70)
            print(f"  Extract:   {self.metrics['extract_time']:.3f}s")
            print(f"  Transform: {self.metrics['transform_time']:.3f}s")
            print(f"  Load:      {self.metrics['load_time']:.3f}s")
            print(f"  Detect:    {self.metrics['detect_time']:.3f}s")
            print(f"  TOTAL:     {total_duration:.3f}s")
            print("="*70)
            
            return {
                'success': True,
                'processed_data': processed_df,
                'anomaly_report': anomaly_report,
                'metrics': self.metrics,
                'output_files': {
                    'csv': csv_path,
                    'summary': summary_path,
                    'anomalies': saved_anomalies
                }
            }
            
        except FileNotFoundError as e:
            print(f"\n❌ FILE ERROR: {str(e)}")
            print("\nTroubleshooting:")
            print("  1. Run 'python generate_logs.py' to create sample data")
            print("  2. Ensure you're running from the project root directory")
            print(f"  3. Check that {self.input_dir}/{log_filename} exists")
            return {'success': False, 'error': str(e), 'error_type': 'FileNotFoundError'}
            
        except ValueError as e:
            print(f"\n❌ DATA ERROR: {str(e)}")
            print("\nCheck:")
            print("  1. Log file format matches expected SSH auth log format")
            print("  2. Review failed parsing samples above")
            return {'success': False, 'error': str(e), 'error_type': 'ValueError'}
            
        except Exception as e:
            print(f"\n❌ PIPELINE FAILED: {str(e)}")
            import traceback
            traceback.print_exc()
            return {'success': False, 'error': str(e), 'error_type': type(e).__name__}

def main():
    """Entry point for the pipeline"""
    print("\n🔐 Intrusion Detection Pipeline")
    print("Author: Your Name | Portfolio Project\n")
    
    pipeline = IntrusionDetectionPipeline()
    result = pipeline.run()
    
    if result['success']:
        print("\n✅ PIPELINE EXECUTED SUCCESSFULLY!")
        print("\n📋 Next Steps:")
        print("  1. Review anomaly reports in output/processed/")
        print("  2. Run visualizations:")
        print("     cd notebooks && jupyter notebook analysis.ipynb")
        print("  3. Customize detection thresholds in src/detect_anomalies.py")
        print("  4. Add to your portfolio with screenshots and metrics")
        print("\n💡 Tip: Share your results on LinkedIn with #DataEngineering #Cybersecurity\n")
        sys.exit(0)
    else:
        print(f"\n❌ PIPELINE FAILED: {result.get('error_type', 'Unknown error')}")
        print(f"   {result.get('error', 'No error details available')}")
        print("\n📖 Check the documentation or error messages above for help.\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
