"""
LOAD Module: Store processed data
Part of the Intrusion Detection ETL Pipeline

Fixed:
- Parquet dependency properly handled
- Empty DataFrame validation
- Relative path handling
"""
import pandas as pd
import os
from datetime import datetime
from pathlib import Path

class DataLoader:
    """Handles loading of processed data to various storage formats"""
    
    def __init__(self, output_directory: str = None):
        """
        Initialize loader with output directory
        
        Args:
            output_directory: Path to output directory (relative or absolute)
                            If None, defaults to 'output/processed'
        """
        if output_directory is None:
            # FIXED: Dynamic path resolution
            project_root = Path(__file__).parent.parent
            output_directory = project_root / 'output' / 'processed'
        
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(parents=True, exist_ok=True)
        
    def load_to_csv(self, df: pd.DataFrame, filename: str = None) -> str:
        """
        Load DataFrame to CSV file
        
        Args:
            df: Processed DataFrame
            filename: Output filename (auto-generated if None)
            
        Returns:
            Path to saved file
            
        Raises:
            ValueError: If DataFrame is empty
        """
        # FIXED: Validate DataFrame before saving
        if df is None or df.empty:
            raise ValueError("Cannot save empty DataFrame to CSV")
        
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'processed_logs_{timestamp}.csv'
        
        filepath = self.output_directory / filename
        df.to_csv(filepath, index=False)
        
        file_size_kb = filepath.stat().st_size / 1024
        
        print(f"✓ Loaded {len(df):,} records to {filepath}")
        print(f"  - File size: {file_size_kb:.2f} KB")
        
        return str(filepath)
    
    def load_to_parquet(self, df: pd.DataFrame, filename: str = None) -> str:
        """
        Load DataFrame to Parquet file (more efficient for large datasets)
        
        FIXED: Proper error handling for missing parquet engine
        """
        # FIXED: Validate DataFrame
        if df is None or df.empty:
            raise ValueError("Cannot save empty DataFrame to Parquet")
        
        try:
            if filename is None:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                filename = f'processed_logs_{timestamp}.parquet'
            
            filepath = self.output_directory / filename
            
            # Convert datetime columns to ensure compatibility
            df_copy = df.copy()
            for col in df_copy.select_dtypes(include=['datetime64']).columns:
                df_copy[col] = pd.to_datetime(df_copy[col])
            
            df_copy.to_parquet(filepath, index=False, engine='pyarrow')
            
            file_size_kb = filepath.stat().st_size / 1024
            
            print(f"✓ Loaded {len(df):,} records to {filepath} (Parquet format)")
            print(f"  - File size: {file_size_kb:.2f} KB (compressed)")
            
            return str(filepath)
            
        except ImportError:
            print("⚠ Warning: pyarrow not installed. Install with: pip install pyarrow")
            print("  Falling back to CSV format...")
            return self.load_to_csv(df, filename.replace('.parquet', '.csv'))
    
    def create_summary_stats(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Generate summary statistics for the processed data
        
        FIXED: Handle empty DataFrames gracefully
        """
        if df is None or df.empty:
            return pd.DataFrame([{
                'total_logs': 0,
                'unique_ips': 0,
                'unique_users': 0,
                'failed_logins': 0,
                'success_rate': 0.0,
                'internal_traffic_pct': 0.0,
                'date_range_start': None,
                'date_range_end': None,
                'error': 'No data to analyze'
            }])
        
        summary = {
            'total_logs': len(df),
            'unique_ips': df['source_ip'].nunique(),
            'unique_users': df['username'].nunique(),
            'failed_logins': int(df['is_failed_login'].sum()),
            'success_rate': round((1 - df['is_failed_login'].mean()) * 100, 2),
            'internal_traffic_pct': round(df['is_internal_ip'].mean() * 100, 2),
            'date_range_start': df['timestamp'].min(),
            'date_range_end': df['timestamp'].max(),
            'time_span_hours': round((df['timestamp'].max() - df['timestamp'].min()).total_seconds() / 3600, 2)
        }
        
        return pd.DataFrame([summary])
    
    def load_anomalies(self, anomaly_dict: dict) -> dict:
        """
        Save all anomaly reports to separate files
        
        Args:
            anomaly_dict: Dictionary containing anomaly DataFrames
            
        Returns:
            Dictionary of saved file paths
        """
        saved_files = {}
        
        anomaly_types = {
            'brute_force_attacks': 'anomaly_brute_force.csv',
            'vulnerable_account_targeting': 'anomaly_vulnerable_accounts.csv',
            'geographic_anomalies': 'anomaly_geographic.csv',
            'possible_breaches': 'anomaly_breaches.csv'
        }
        
        for key, filename in anomaly_types.items():
            if key in anomaly_dict and not anomaly_dict[key].empty:
                filepath = self.load_to_csv(anomaly_dict[key], filename)
                saved_files[key] = filepath
        
        return saved_files

if __name__ == "__main__":
    # Test the loader
    sample_data = pd.DataFrame({
        'timestamp': [datetime.now()],
        'status': ['Failed'],
        'username': ['admin'],
        'source_ip': ['45.142.212.61'],
        'port': [54321],
        'is_failed_login': [True],
        'is_internal_ip': [False]
    })
    
    loader = DataLoader()
    print(f"Output directory: {loader.output_directory}")
    
    csv_path = loader.load_to_csv(sample_data, 'test_output.csv')
    print(f"\nSaved to: {csv_path}")
    
    stats = loader.create_summary_stats(sample_data)
    print(f"\nSummary stats:\n{stats.T}")
