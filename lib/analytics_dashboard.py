#!/usr/bin/env python3
"""
Albator Analytics Dashboard
Provides security analytics and trend analysis
"""

import os
import sys
import json
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import numpy as np

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from compliance_reporter import ComplianceReporter, ComplianceReport

@dataclass
class SecurityMetric:
    """Represents a security metric data point"""
    timestamp: str
    metric_name: str
    metric_value: float
    metric_type: str  # compliance_score, vulnerability_count, security_level
    system_id: str
    framework: str = ""
    category: str = ""

@dataclass
class TrendAnalysis:
    """Represents trend analysis results"""
    metric_name: str
    trend_direction: str  # improving, declining, stable
    trend_strength: float  # 0-1 scale
    current_value: float
    previous_value: float
    change_percentage: float
    recommendation: str

class AnalyticsDashboard:
    """Provides security analytics and trend analysis"""
    
    def __init__(self, db_path: str = "analytics.db"):
        """Initialize the analytics dashboard"""
        self.logger = get_logger("analytics_dashboard")
        self.db_path = db_path
        self.compliance_reporter = ComplianceReporter()
        self._init_database()
        
        # Set up matplotlib for headless operation
        plt.switch_backend('Agg')
        sns.set_style("whitegrid")
        plt.rcParams['figure.figsize'] = (12, 8)
    
    def _init_database(self):
        """Initialize the analytics database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create metrics table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS security_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metric_type TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    framework TEXT,
                    category TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create compliance reports table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS compliance_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    report_id TEXT UNIQUE NOT NULL,
                    framework TEXT NOT NULL,
                    system_id TEXT NOT NULL,
                    compliance_score REAL NOT NULL,
                    total_checks INTEGER NOT NULL,
                    passed_checks INTEGER NOT NULL,
                    failed_checks INTEGER NOT NULL,
                    error_checks INTEGER NOT NULL,
                    generated_at TEXT NOT NULL,
                    report_data TEXT NOT NULL
                )
            ''')
            
            # Create system information table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS system_info (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    system_id TEXT UNIQUE NOT NULL,
                    hostname TEXT,
                    macos_version TEXT,
                    hardware_model TEXT,
                    last_seen TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create indexes for better performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON security_metrics(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_metrics_system ON security_metrics(system_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_system ON compliance_reports(system_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports_framework ON compliance_reports(framework)')
            
            conn.commit()
            conn.close()
            
            self.logger.info("Analytics database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            raise
    
    def record_compliance_report(self, report: ComplianceReport, system_id: str = None):
        """Record a compliance report in the analytics database"""
        log_operation_start(f"record_compliance_report: {report.report_id}")
        
        try:
            if system_id is None:
                system_id = report.system_info.get('hostname', 'unknown')
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert or update system info
            cursor.execute('''
                INSERT OR REPLACE INTO system_info 
                (system_id, hostname, macos_version, hardware_model, last_seen)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                system_id,
                report.system_info.get('hostname', 'Unknown'),
                report.system_info.get('macos_version', 'Unknown'),
                report.system_info.get('hardware_model', 'Unknown'),
                datetime.now().isoformat()
            ))
            
            # Insert compliance report
            cursor.execute('''
                INSERT OR REPLACE INTO compliance_reports
                (report_id, framework, system_id, compliance_score, total_checks, 
                 passed_checks, failed_checks, error_checks, generated_at, report_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                report.report_id,
                report.framework,
                system_id,
                report.summary['compliance_score'],
                report.summary['total_checks'],
                report.summary['passed'],
                report.summary['failed'],
                report.summary['errors'],
                report.generated_at,
                json.dumps(asdict(report))
            ))
            
            # Record individual metrics
            timestamp = report.generated_at
            
            # Overall compliance score
            self._insert_metric(cursor, timestamp, 'compliance_score', 
                              report.summary['compliance_score'], 'compliance_score', 
                              system_id, report.framework)
            
            # Category-specific scores
            for category, stats in report.summary['category_summary'].items():
                if stats['total'] > 0:
                    category_score = (stats['passed'] / stats['total']) * 100
                    self._insert_metric(cursor, timestamp, f'category_{category.lower().replace(" ", "_")}', 
                                      category_score, 'category_score', system_id, 
                                      report.framework, category)
            
            # Severity-specific scores
            for severity, stats in report.summary['severity_summary'].items():
                if stats['total'] > 0:
                    severity_score = (stats['passed'] / stats['total']) * 100
                    self._insert_metric(cursor, timestamp, f'severity_{severity}', 
                                      severity_score, 'severity_score', system_id, 
                                      report.framework, severity)
            
            conn.commit()
            conn.close()
            
            log_operation_success(f"record_compliance_report: {report.report_id}")
            
        except Exception as e:
            log_operation_failure(f"record_compliance_report: {report.report_id}", str(e))
            raise
    
    def _insert_metric(self, cursor, timestamp: str, metric_name: str, metric_value: float,
                      metric_type: str, system_id: str, framework: str = "", category: str = ""):
        """Insert a metric into the database"""
        cursor.execute('''
            INSERT INTO security_metrics
            (timestamp, metric_name, metric_value, metric_type, system_id, framework, category)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (timestamp, metric_name, metric_value, metric_type, system_id, framework, category))
    
    def get_compliance_trends(self, system_id: str = None, framework: str = None, 
                            days: int = 30) -> List[TrendAnalysis]:
        """Get compliance trend analysis"""
        log_operation_start("get_compliance_trends")
        
        try:
            conn = sqlite3.connect(self.db_path)
            
            # Build query conditions
            conditions = ["metric_type = 'compliance_score'"]
            params = []
            
            if system_id:
                conditions.append("system_id = ?")
                params.append(system_id)
            
            if framework:
                conditions.append("framework = ?")
                params.append(framework)
            
            # Get recent data
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            conditions.append("timestamp >= ?")
            params.append(cutoff_date)
            
            query = f'''
                SELECT metric_name, metric_value, timestamp, system_id, framework
                FROM security_metrics
                WHERE {" AND ".join(conditions)}
                ORDER BY timestamp DESC
            '''
            
            df = pd.read_sql_query(query, conn, params=params)
            conn.close()
            
            if df.empty:
                return []
            
            # Analyze trends
            trends = []
            
            # Group by metric and system
            for (metric_name, system_id, framework), group in df.groupby(['metric_name', 'system_id', 'framework']):
                if len(group) < 2:
                    continue
                
                group = group.sort_values('timestamp')
                current_value = group.iloc[-1]['metric_value']
                previous_value = group.iloc[0]['metric_value']
                
                # Calculate trend
                change_percentage = ((current_value - previous_value) / previous_value * 100) if previous_value != 0 else 0
                
                # Determine trend direction and strength
                if abs(change_percentage) < 2:
                    trend_direction = "stable"
                    trend_strength = 0.1
                elif change_percentage > 0:
                    trend_direction = "improving"
                    trend_strength = min(abs(change_percentage) / 20, 1.0)
                else:
                    trend_direction = "declining"
                    trend_strength = min(abs(change_percentage) / 20, 1.0)
                
                # Generate recommendation
                recommendation = self._generate_trend_recommendation(
                    metric_name, trend_direction, current_value, change_percentage
                )
                
                trends.append(TrendAnalysis(
                    metric_name=metric_name,
                    trend_direction=trend_direction,
                    trend_strength=trend_strength,
                    current_value=current_value,
                    previous_value=previous_value,
                    change_percentage=change_percentage,
                    recommendation=recommendation
                ))
            
            log_operation_success("get_compliance_trends", {"trends_count": len(trends)})
            return trends
            
        except Exception as e:
            log_operation_failure("get_compliance_trends", str(e))
            return []
    
    def _generate_trend_recommendation(self, metric_name: str, trend_direction: str, 
                                     current_value: float, change_percentage: float) -> str:
        """Generate recommendations based on trend analysis"""
        if metric_name == "compliance_score":
            if trend_direction == "declining":
                if current_value < 70:
                    return "URGENT: Compliance score is declining and below acceptable threshold. Immediate action required."
                else:
                    return "WARNING: Compliance score is declining. Review recent changes and address failing checks."
            elif trend_direction == "improving":
                return "GOOD: Compliance score is improving. Continue current security practices."
            else:
                if current_value < 80:
                    return "ATTENTION: Compliance score is stable but could be improved. Focus on failing checks."
                else:
                    return "EXCELLENT: Compliance score is stable and at good level. Maintain current practices."
        
        return f"Monitor {metric_name} trends and investigate if decline continues."
    
    def generate_security_dashboard(self, output_path: str = "security_dashboard.html", 
                                  system_id: str = None, days: int = 30):
        """Generate a comprehensive security dashboard"""
        log_operation_start("generate_security_dashboard")
        
        try:
            # Get data
            trends = self.get_compliance_trends(system_id=system_id, days=days)
            compliance_data = self._get_compliance_data(system_id=system_id, days=days)
            system_summary = self._get_system_summary()
            
            # Generate charts
            charts = self._generate_charts(compliance_data, system_id, days)
            
            # Create HTML dashboard
            html_content = self._create_dashboard_html(trends, compliance_data, system_summary, charts)
            
            with open(output_path, 'w') as f:
                f.write(html_content)
            
            log_operation_success("generate_security_dashboard", {"output_path": output_path})
            return True
            
        except Exception as e:
            log_operation_failure("generate_security_dashboard", str(e))
            return False
    
    def _get_compliance_data(self, system_id: str = None, days: int = 30) -> pd.DataFrame:
        """Get compliance data for analysis"""
        conn = sqlite3.connect(self.db_path)
        
        conditions = []
        params = []
        
        if system_id:
            conditions.append("system_id = ?")
            params.append(system_id)
        
        cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
        conditions.append("generated_at >= ?")
        params.append(cutoff_date)
        
        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        
        query = f'''
            SELECT * FROM compliance_reports
            {where_clause}
            ORDER BY generated_at DESC
        '''
        
        df = pd.read_sql_query(query, conn, params=params)
        conn.close()
        
        return df
    
    def _get_system_summary(self) -> Dict[str, Any]:
        """Get system summary statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Get system counts
        cursor.execute("SELECT COUNT(DISTINCT system_id) FROM system_info")
        total_systems = cursor.fetchone()[0]
        
        # Get recent activity
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        cursor.execute("SELECT COUNT(DISTINCT system_id) FROM compliance_reports WHERE generated_at >= ?", (week_ago,))
        active_systems = cursor.fetchone()[0]
        
        # Get framework usage
        cursor.execute('''
            SELECT framework, COUNT(*) as count 
            FROM compliance_reports 
            GROUP BY framework 
            ORDER BY count DESC
        ''')
        framework_usage = dict(cursor.fetchall())
        
        # Get average compliance score
        cursor.execute("SELECT AVG(compliance_score) FROM compliance_reports WHERE generated_at >= ?", (week_ago,))
        avg_compliance = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            "total_systems": total_systems,
            "active_systems": active_systems,
            "framework_usage": framework_usage,
            "avg_compliance_score": round(avg_compliance, 2)
        }
    
    def _generate_charts(self, compliance_data: pd.DataFrame, system_id: str = None, days: int = 30) -> Dict[str, str]:
        """Generate charts for the dashboard"""
        charts = {}
        
        if compliance_data.empty:
            return charts
        
        try:
            # Compliance score trend chart
            plt.figure(figsize=(12, 6))
            compliance_data['generated_at'] = pd.to_datetime(compliance_data['generated_at'])
            
            if system_id:
                system_data = compliance_data[compliance_data['system_id'] == system_id]
                plt.plot(system_data['generated_at'], system_data['compliance_score'], 
                        marker='o', linewidth=2, markersize=6)
                plt.title(f'Compliance Score Trend - {system_id}')
            else:
                # Group by date and calculate average
                daily_avg = compliance_data.groupby(compliance_data['generated_at'].dt.date)['compliance_score'].mean()
                plt.plot(daily_avg.index, daily_avg.values, marker='o', linewidth=2, markersize=6)
                plt.title('Average Compliance Score Trend')
            
            plt.xlabel('Date')
            plt.ylabel('Compliance Score (%)')
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            plt.tight_layout()
            
            chart_path = 'compliance_trend.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            charts['compliance_trend'] = chart_path
            
            # Framework comparison chart
            plt.figure(figsize=(10, 6))
            framework_scores = compliance_data.groupby('framework')['compliance_score'].mean()
            bars = plt.bar(framework_scores.index, framework_scores.values, 
                          color=['#3498db', '#e74c3c', '#2ecc71', '#f39c12'])
            plt.title('Average Compliance Score by Framework')
            plt.xlabel('Framework')
            plt.ylabel('Average Compliance Score (%)')
            plt.xticks(rotation=45)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                plt.text(bar.get_x() + bar.get_width()/2., height + 1,
                        f'{height:.1f}%', ha='center', va='bottom')
            
            plt.tight_layout()
            chart_path = 'framework_comparison.png'
            plt.savefig(chart_path, dpi=150, bbox_inches='tight')
            plt.close()
            charts['framework_comparison'] = chart_path
            
            # System performance heatmap (if multiple systems)
            if not system_id and len(compliance_data['system_id'].unique()) > 1:
                plt.figure(figsize=(12, 8))
                
                # Create pivot table for heatmap
                pivot_data = compliance_data.pivot_table(
                    values='compliance_score', 
                    index='system_id', 
                    columns='framework', 
                    aggfunc='mean'
                )
                
                sns.heatmap(pivot_data, annot=True, fmt='.1f', cmap='RdYlGn', 
                           center=80, vmin=0, vmax=100, cbar_kws={'label': 'Compliance Score (%)'})
                plt.title('System Compliance Heatmap by Framework')
                plt.xlabel('Framework')
                plt.ylabel('System')
                plt.tight_layout()
                
                chart_path = 'system_heatmap.png'
                plt.savefig(chart_path, dpi=150, bbox_inches='tight')
                plt.close()
                charts['system_heatmap'] = chart_path
            
        except Exception as e:
            self.logger.error(f"Error generating charts: {e}")
        
        return charts
    
    def _create_dashboard_html(self, trends: List[TrendAnalysis], compliance_data: pd.DataFrame,
                             system_summary: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Create HTML dashboard content"""
        
        # Generate trends HTML
        trends_html = ""
        for trend in trends:
            trend_color = {
                "improving": "#27ae60",
                "declining": "#e74c3c", 
                "stable": "#f39c12"
            }.get(trend.trend_direction, "#95a5a6")
            
            trends_html += f"""
            <div class="trend-item">
                <h4>{trend.metric_name.replace('_', ' ').title()}</h4>
                <div class="trend-indicator" style="color: {trend_color};">
                    {trend.trend_direction.upper()} ({trend.change_percentage:+.1f}%)
                </div>
                <div class="trend-values">
                    Current: {trend.current_value:.1f} | Previous: {trend.previous_value:.1f}
                </div>
                <div class="trend-recommendation">
                    {trend.recommendation}
                </div>
            </div>
            """
        
        # Generate charts HTML
        charts_html = ""
        for chart_name, chart_path in charts.items():
            charts_html += f"""
            <div class="chart-container">
                <img src="{chart_path}" alt="{chart_name}" class="chart-image">
            </div>
            """
        
        # Generate recent reports table
        recent_reports_html = ""
        if not compliance_data.empty:
            recent_data = compliance_data.head(10)
            for _, row in recent_data.iterrows():
                recent_reports_html += f"""
                <tr>
                    <td>{row['system_id']}</td>
                    <td>{row['framework']}</td>
                    <td>{row['compliance_score']:.1f}%</td>
                    <td>{row['passed_checks']}/{row['total_checks']}</td>
                    <td>{row['generated_at'][:19]}</td>
                </tr>
                """
        
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Albator Security Analytics Dashboard</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f8f9fa;
            color: #333;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
            font-weight: 300;
        }}
        .header p {{
            margin: 10px 0 0 0;
            opacity: 0.9;
        }}
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .card {{
            background: white;
            border-radius: 10px;
            padding: 20px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-left: 4px solid #667eea;
        }}
        .card h3 {{
            margin-top: 0;
            color: #667eea;
            border-bottom: 2px solid #f1f3f4;
            padding-bottom: 10px;
        }}
        .metric-value {{
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
            margin: 10px 0;
        }}
        .metric-label {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .trend-item {{
            background: #f8f9fa;
            padding: 15px;
            margin: 10px 0;
            border-radius: 8px;
            border-left: 4px solid #3498db;
        }}
        .trend-indicator {{
            font-weight: bold;
            font-size: 1.1em;
            margin: 5px 0;
        }}
        .trend-values {{
            color: #7f8c8d;
            font-size: 0.9em;
            margin: 5px 0;
        }}
        .trend-recommendation {{
            background: #e8f4f8;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
            font-size: 0.9em;
            border-left: 3px solid #3498db;
        }}
        .chart-container {{
            text-align: center;
            margin: 20px 0;
        }}
        .chart-image {{
            max-width: 100%;
            height: auto;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #e9ecef;
        }}
        th {{
            background: #667eea;
            color: white;
            font-weight: 500;
        }}
        tr:hover {{
            background: #f8f9fa;
        }}
        .status-good {{ color: #27ae60; font-weight: bold; }}
        .status-warning {{ color: #f39c12; font-weight: bold; }}
        .status-danger {{ color: #e74c3c; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Albator Security Analytics Dashboard</h1>
        <p>Comprehensive security monitoring and compliance tracking</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="dashboard-grid">
        <div class="card">
            <h3>📊 System Overview</h3>
            <div class="metric-value">{system_summary['total_systems']}</div>
            <div class="metric-label">Total Systems</div>
            <div class="metric-value">{system_summary['active_systems']}</div>
            <div class="metric-label">Active This Week</div>
        </div>
        
        <div class="card">
            <h3>🎯 Compliance Score</h3>
            <div class="metric-value {
                'status-good' if system_summary['avg_compliance_score'] >= 80 
                else 'status-warning' if system_summary['avg_compliance_score'] >= 60 
                else 'status-danger'
            }">{system_summary['avg_compliance_score']:.1f}%</div>
            <div class="metric-label">Average Compliance</div>
        </div>
        
        <div class="card">
            <h3>🔧 Framework Usage</h3>
            {chr(10).join([f'<div><strong>{framework}:</strong> {count} reports</div>' 
                          for framework, count in system_summary['framework_usage'].items()])}
        </div>
    </div>
    
    <div class="card">
        <h3>📈 Security Trends</h3>
        {trends_html if trends_html else '<p>No trend data available. Generate more compliance reports to see trends.</p>'}
    </div>
    
    <div class="card">
        <h3>📊 Analytics Charts</h3>
        {charts_html if charts_html else '<p>No chart data available.</p>'}
    </div>
    
    <div class="card">
        <h3>📋 Recent Compliance Reports</h3>
        <table>
            <thead>
                <tr>
                    <th>System</th>
                    <th>Framework</th>
                    <th>Score</th>
                    <th>Checks</th>
                    <th>Generated</th>
                </tr>
            </thead>
            <tbody>
                {recent_reports_html if recent_reports_html else '<tr><td colspan="5">No recent reports available</td></tr>'}
            </tbody>
        </table>
    </div>
</body>
</html>
        """
        
        return html_template
    
    def export_analytics_data(self, output_path: str, format: str = "csv", 
                            system_id: str = None, days: int = 30) -> bool:
        """Export analytics data for external analysis"""
        log_operation_start(f"export_analytics_data: {format}")
        
        try:
            # Get compliance data
            compliance_data = self._get_compliance_data(system_id=system_id, days=days)
            
            if compliance_data.empty:
                self.logger.warning("No data available for export")
                return False
            
            if format.lower() == "csv":
                compliance_data.to_csv(output_path, index=False)
            elif format.lower() == "json":
                compliance_data.to_json(output_path, orient='records', indent=2)
            elif format.lower() == "excel":
                compliance_data.to_excel(output_path, index=False)
            else:
                raise ValueError(f"Unsupported format: {format}")
            
            log_operation_success(f"export_analytics_data: {format}", {"output_path": output_path})
            return True
            
        except Exception as e:
            log_operation_failure(f"export_analytics_data: {format}", str(e))
            return False

def main():
    """Main function for analytics dashboard"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator Analytics Dashboard")
    parser.add_argument("--db-path", default="analytics.db", help="Database path")
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Generate dashboard
    dashboard_parser = subparsers.add_parser("dashboard", help="Generate security dashboard")
    dashboard_parser.add_argument("--output", default="security_dashboard.html", help="Output file path")
    dashboard_parser.add_argument("--system", help="System ID to focus on")
    dashboard_parser.add_argument("--days", type=int, default=30, help="Days of data to include")
    
    # Export data
    export_parser = subparsers.add_parser("export", help="Export analytics data")
    export_parser.add_argument("output", help="Output file path")
    export_parser.add_argument("--format", choices=["csv", "json", "excel"], default="csv", help="Export format")
    export_parser.add_argument("--system", help="System ID to filter")
    export_parser.add_argument("--days", type=int, default=30, help="Days of data to include")
    
    # Show trends
    trends_parser = subparsers.add_parser("trends", help="Show compliance trends")
    trends_parser.add_argument("--system", help="System ID to filter")
    trends_parser.add_argument("--framework", help="Framework to filter")
    trends_parser.add_argument("--days", type=int, default=30, help="Days of data to analyze")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_
