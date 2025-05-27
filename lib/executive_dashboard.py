#!/usr/bin/env python3
"""
Albator Executive Dashboard
Provides executive-level security insights and reporting
"""

import os
import sys
import json
import base64
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from io import BytesIO

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from analytics_dashboard import AnalyticsDashboard
from compliance_reporter import ComplianceReporter
from ml_security_engine import MLSecurityEngine
from fleet_manager import FleetManager
from executive_dashboard_helpers import ExecutiveDashboardHelpers

@dataclass
class ExecutiveMetric:
    """Represents an executive-level metric"""
    metric_name: str
    current_value: float
    previous_value: float
    target_value: float
    trend: str  # up, down, stable
    status: str  # on_track, at_risk, critical
    percentage_change: float
    forecast_30d: float

@dataclass
class RiskAssessment:
    """Represents enterprise risk assessment"""
    overall_risk_score: float
    risk_category: str  # low, medium, high, critical
    top_risks: List[Dict[str, Any]]
    risk_trend: str
    mitigation_priority: List[str]
    estimated_exposure: float  # In dollars

@dataclass
class ROICalculation:
    """Represents security ROI calculation"""
    investment_amount: float
    prevented_incidents: int
    cost_savings: float
    productivity_gains: float
    total_roi: float
    roi_percentage: float
    payback_period_months: int

class ExecutiveDashboard(ExecutiveDashboardHelpers):
    """Executive Dashboard for C-level security insights"""
    
    def __init__(self):
        """Initialize the Executive Dashboard"""
        self.logger = get_logger("executive_dashboard")
        self.analytics = AnalyticsDashboard()
        self.compliance = ComplianceReporter()
        self.ml_engine = MLSecurityEngine()
        self.fleet_manager = FleetManager()
        
        # Industry benchmarks for comparison
        self.industry_benchmarks = {
            "compliance_score": 85.0,
            "incident_rate": 2.5,  # per 100 systems per month
            "mttr": 4.0,  # Mean time to remediate in hours
            "security_investment_percentage": 8.5  # % of IT budget
        }
    
    def generate_executive_summary(self, time_period_days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive executive summary"""
        log_operation_start("generate_executive_summary")
        
        try:
            # Gather all metrics
            kpis = self._calculate_kpis(time_period_days)
            risk_assessment = self._assess_enterprise_risk()
            compliance_status = self._get_compliance_overview()
            security_posture = self._evaluate_security_posture()
            roi_analysis = self._calculate_security_roi(time_period_days)
            
            # Generate insights
            key_insights = self._generate_key_insights(kpis, risk_assessment, compliance_status)
            recommendations = self._generate_executive_recommendations(risk_assessment, compliance_status)
            
            summary = {
                "report_date": datetime.now().isoformat(),
                "reporting_period_days": time_period_days,
                "executive_metrics": {
                    "overall_security_score": security_posture["overall_score"],
                    "risk_level": risk_assessment.risk_category,
                    "compliance_percentage": compliance_status["average_compliance"],
                    "fleet_health": security_posture["fleet_health_score"],
                    "roi_percentage": roi_analysis.roi_percentage
                },
                "key_performance_indicators": kpis,
                "risk_assessment": asdict(risk_assessment),
                "compliance_overview": compliance_status,
                "security_posture": security_posture,
                "roi_analysis": asdict(roi_analysis),
                "key_insights": key_insights,
                "strategic_recommendations": recommendations,
                "benchmark_comparison": self._compare_to_industry_benchmarks(kpis)
            }
            
            log_operation_success("generate_executive_summary", {
                "security_score": security_posture["overall_score"],
                "risk_level": risk_assessment.risk_category
            })
            
            return summary
            
        except Exception as e:
            log_operation_failure("generate_executive_summary", str(e))
            raise
    
    def _calculate_kpis(self, days: int) -> List[ExecutiveMetric]:
        """Calculate key performance indicators"""
        kpis = []
        
        # Security Incident Rate
        current_incidents = self._get_incident_count(days)
        previous_incidents = self._get_incident_count(days, offset_days=days)
        incident_rate = ExecutiveMetric(
            metric_name="Security Incident Rate",
            current_value=current_incidents,
            previous_value=previous_incidents,
            target_value=self.industry_benchmarks["incident_rate"],
            trend="down" if current_incidents < previous_incidents else "up",
            status="on_track" if current_incidents <= self.industry_benchmarks["incident_rate"] else "at_risk",
            percentage_change=self._calculate_percentage_change(previous_incidents, current_incidents),
            forecast_30d=self._forecast_value(current_incidents, previous_incidents)
        )
        kpis.append(incident_rate)
        
        # Mean Time to Remediate
        current_mttr = self._calculate_mttr(days)
        previous_mttr = self._calculate_mttr(days, offset_days=days)
        mttr_metric = ExecutiveMetric(
            metric_name="Mean Time to Remediate (hours)",
            current_value=current_mttr,
            previous_value=previous_mttr,
            target_value=self.industry_benchmarks["mttr"],
            trend="down" if current_mttr < previous_mttr else "up",
            status="on_track" if current_mttr <= self.industry_benchmarks["mttr"] else "at_risk",
            percentage_change=self._calculate_percentage_change(previous_mttr, current_mttr),
            forecast_30d=self._forecast_value(current_mttr, previous_mttr)
        )
        kpis.append(mttr_metric)
        
        # System Compliance Rate
        compliance_data = self.analytics.get_compliance_trends(days=days)
        if compliance_data:
            current_compliance = compliance_data[-1].current_value if compliance_data else 0
            previous_compliance = compliance_data[0].previous_value if compliance_data else 0
            compliance_metric = ExecutiveMetric(
                metric_name="System Compliance Rate (%)",
                current_value=current_compliance,
                previous_value=previous_compliance,
                target_value=self.industry_benchmarks["compliance_score"],
                trend="up" if current_compliance > previous_compliance else "down",
                status="on_track" if current_compliance >= self.industry_benchmarks["compliance_score"] else "at_risk",
                percentage_change=self._calculate_percentage_change(previous_compliance, current_compliance),
                forecast_30d=self._forecast_value(current_compliance, previous_compliance)
            )
            kpis.append(compliance_metric)
        
        # Vulnerability Exposure Window
        current_exposure = self._calculate_exposure_window(days)
        previous_exposure = self._calculate_exposure_window(days, offset_days=days)
        exposure_metric = ExecutiveMetric(
            metric_name="Avg Vulnerability Exposure (days)",
            current_value=current_exposure,
            previous_value=previous_exposure,
            target_value=7.0,  # Target: patch within 7 days
            trend="down" if current_exposure < previous_exposure else "up",
            status="on_track" if current_exposure <= 7.0 else "critical",
            percentage_change=self._calculate_percentage_change(previous_exposure, current_exposure),
            forecast_30d=self._forecast_value(current_exposure, previous_exposure)
        )
        kpis.append(exposure_metric)
        
        return kpis
    
    def _assess_enterprise_risk(self) -> RiskAssessment:
        """Assess overall enterprise security risk"""
        # Get fleet data
        fleet_hosts = self.fleet_manager.list_hosts()
        
        # Calculate risk scores
        risk_scores = []
        top_risks = []
        
        for host in fleet_hosts:
            # Get system data for ML prediction
            system_data = self._get_system_security_data(host['host_id'])
            prediction = self.ml_engine.predict_security_risk(system_data)
            
            risk_scores.append(prediction.predicted_value)
            
            if prediction.predicted_value > 0.7:
                top_risks.append({
                    "system": host['hostname'],
                    "risk_score": prediction.predicted_value,
                    "factors": prediction.factors[:3]  # Top 3 factors
                })
        
        # Calculate overall risk
        overall_risk = np.mean(risk_scores) if risk_scores else 0.5
        
        # Determine risk category
        if overall_risk <= 0.2:
            risk_category = "low"
        elif overall_risk <= 0.5:
            risk_category = "medium"
        elif overall_risk <= 0.8:
            risk_category = "high"
        else:
            risk_category = "critical"
        
        # Sort top risks
        top_risks.sort(key=lambda x: x['risk_score'], reverse=True)
        
        # Calculate risk trend
        historical_risk = self._get_historical_risk_scores(30)
        risk_trend = "increasing" if len(historical_risk) > 1 and historical_risk[-1] > historical_risk[0] else "decreasing"
        
        # Mitigation priorities
        mitigation_priority = self._generate_mitigation_priorities(top_risks)
        
        # Estimate financial exposure
        estimated_exposure = self._estimate_financial_exposure(overall_risk, len(fleet_hosts))
        
        return RiskAssessment(
            overall_risk_score=float(overall_risk),
            risk_category=risk_category,
            top_risks=top_risks[:10],  # Top 10 risks
            risk_trend=risk_trend,
            mitigation_priority=mitigation_priority[:5],  # Top 5 priorities
            estimated_exposure=estimated_exposure
        )
    
    def _get_compliance_overview(self) -> Dict[str, Any]:
        """Get compliance overview across frameworks"""
        frameworks = ["nist_800_53", "cis_macos", "iso27001"]
        compliance_scores = {}
        failed_controls = []
        
        for framework in frameworks:
            try:
                # Get latest compliance report
                report = self.compliance.generate_compliance_report(framework)
                score = report.summary["compliance_score"]
                compliance_scores[framework] = score
                
                # Collect failed controls
                for check in report.checks:
                    if check.status == "fail":
                        failed_controls.append({
                            "framework": framework,
                            "control": check.check_id,
                            "title": check.title,
                            "severity": check.severity
                        })
            except:
                compliance_scores[framework] = 0
        
        # Sort failed controls by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        failed_controls.sort(key=lambda x: severity_order.get(x["severity"], 4))
        
        return {
            "framework_scores": compliance_scores,
            "average_compliance": np.mean(list(compliance_scores.values())),
            "critical_failures": [fc for fc in failed_controls if fc["severity"] == "critical"],
            "total_failed_controls": len(failed_controls),
            "compliance_trend": self._calculate_compliance_trend()
        }
    
    def _evaluate_security_posture(self) -> Dict[str, Any]:
        """Evaluate overall security posture"""
        fleet_hosts = self.fleet_manager.list_hosts()
        
        # Security metrics
        encrypted_systems = 0
        firewall_enabled = 0
        updated_systems = 0
        total_systems = len(fleet_hosts)
        
        for host in fleet_hosts:
            system_data = self._get_system_security_data(host['host_id'])
            if system_data.get('filevault_enabled', False):
                encrypted_systems += 1
            if system_data.get('firewall_enabled', False):
                firewall_enabled += 1
            if system_data.get('days_since_last_update', 100) <= 30:
                updated_systems += 1
        
        # Calculate scores
        encryption_score = (encrypted_systems / total_systems * 100) if total_systems > 0 else 0
        firewall_score = (firewall_enabled / total_systems * 100) if total_systems > 0 else 0
        update_score = (updated_systems / total_systems * 100) if total_systems > 0 else 0
        
        # Overall security score
        overall_score = np.mean([encryption_score, firewall_score, update_score])
        
        # Fleet health score (based on various factors)
        fleet_health_score = self._calculate_fleet_health_score()
        
        return {
            "overall_score": float(overall_score),
            "encryption_coverage": float(encryption_score),
            "firewall_coverage": float(firewall_score),
            "patch_compliance": float(update_score),
            "fleet_health_score": float(fleet_health_score),
            "total_systems": total_systems,
            "security_grade": self._calculate_security_grade(overall_score)
        }
    
    def _calculate_security_roi(self, days: int) -> ROICalculation:
        """Calculate security investment ROI"""
        # Estimate investment (placeholder - should come from financial data)
        monthly_investment = 50000  # $50k/month security investment
        investment_amount = (days / 30) * monthly_investment
        
        # Calculate prevented incidents
        baseline_incident_rate = 10  # Expected incidents without security
        actual_incidents = self._get_incident_count(days)
        prevented_incidents = max(0, baseline_incident_rate - actual_incidents)
        
        # Average cost per incident (industry standard)
        cost_per_incident = 150000  # $150k average cost per security incident
        cost_savings = prevented_incidents * cost_per_incident
        
        # Productivity gains from reduced downtime
        downtime_hours_saved = prevented_incidents * 8  # 8 hours average downtime
        productivity_cost_per_hour = 5000  # $5k/hour for organization
        productivity_gains = downtime_hours_saved * productivity_cost_per_hour
        
        # Total ROI
        total_roi = cost_savings + productivity_gains - investment_amount
        roi_percentage = (total_roi / investment_amount * 100) if investment_amount > 0 else 0
        
        # Payback period
        monthly_roi = total_roi / (days / 30) if days > 0 else 0
        payback_period_months = int(investment_amount / monthly_roi) if monthly_roi > 0 else 999
        
        return ROICalculation(
            investment_amount=investment_amount,
            prevented_incidents=prevented_incidents,
            cost_savings=cost_savings,
            productivity_gains=productivity_gains,
            total_roi=total_roi,
            roi_percentage=roi_percentage,
            payback_period_months=payback_period_months
        )
    
    def _generate_key_insights(self, kpis: List[ExecutiveMetric], 
                             risk: RiskAssessment, 
                             compliance: Dict[str, Any]) -> List[str]:
        """Generate key insights for executives"""
        insights = []
        
        # KPI insights
        for kpi in kpis:
            if kpi.status == "critical":
                insights.append(f"⚠️ CRITICAL: {kpi.metric_name} is {kpi.percentage_change:.1f}% above target")
            elif kpi.status == "on_track" and kpi.percentage_change < -10:
                insights.append(f"✅ {kpi.metric_name} improved by {abs(kpi.percentage_change):.1f}%")
        
        # Risk insights
        if risk.risk_category in ["high", "critical"]:
            insights.append(f"🚨 Enterprise risk level is {risk.risk_category.upper()} - immediate action required")
        
        if risk.estimated_exposure > 1000000:
            insights.append(f"💰 Estimated financial exposure: ${risk.estimated_exposure/1000000:.1f}M")
        
        # Compliance insights
        if compliance["average_compliance"] < 80:
            insights.append(f"📋 Compliance below target at {compliance['average_compliance']:.1f}%")
        
        if len(compliance["critical_failures"]) > 0:
            insights.append(f"🔴 {len(compliance['critical_failures'])} critical compliance failures require immediate remediation")
        
        return insights[:5]  # Top 5 insights
    
    def _generate_executive_recommendations(self, risk: RiskAssessment, 
                                          compliance: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate strategic recommendations for executives"""
        recommendations = []
        
        # Risk-based recommendations
        if risk.risk_category in ["high", "critical"]:
            recommendations.append({
                "priority": "critical",
                "recommendation": "Initiate emergency security response plan",
                "impact": "Reduce enterprise risk by 40%",
                "timeline": "Immediate",
                "estimated_cost": "$200,000"
            })
        
        # Compliance recommendations
        if compliance["average_compliance"] < 80:
            recommendations.append({
                "priority": "high",
                "recommendation": "Launch compliance remediation program",
                "impact": "Achieve 90%+ compliance within 60 days",
                "timeline": "30 days",
                "estimated_cost": "$150,000"
            })
        
        # Top risk mitigation
        if risk.mitigation_priority:
            recommendations.append({
                "priority": "high",
                "recommendation": f"Address top risk: {risk.mitigation_priority[0]}",
                "impact": "Reduce overall risk score by 25%",
                "timeline": "14 days",
                "estimated_cost": "$75,000"
            })
        
        # Investment recommendations
        roi_positive_actions = [
            {
                "priority": "medium",
                "recommendation": "Expand automated security monitoring",
                "impact": "Reduce incident detection time by 60%",
                "timeline": "90 days",
                "estimated_cost": "$300,000"
            },
            {
                "priority": "medium",
                "recommendation": "Implement AI-driven threat detection",
                "impact": "Prevent 8 additional incidents annually",
                "timeline": "180 days",
                "estimated_cost": "$500,000"
            }
        ]
        
        recommendations.extend(roi_positive_actions)
        
        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        return recommendations[:5]  # Top 5 recommendations
    
    def generate_risk_heatmap_visualization(self) -> str:
        """Generate risk heatmap visualization"""
        log_operation_start("generate_risk_heatmap_visualization")
        
        try:
            # Get fleet data
            fleet_hosts = self.fleet_manager.list_hosts()
            heatmap_data = self.ml_engine.generate_risk_heatmap([
                self._get_system_security_data(host['host_id']) 
                for host in fleet_hosts
            ])
            
            # Create visualization
            plt.figure(figsize=(12, 8))
            
            # Prepare data for heatmap
            systems = [item['hostname'] for item in heatmap_data['heatmap'][:20]]  # Top 20
            categories = ['Firewall', 'Encryption', 'Updates', 'Compliance', 'Overall']
            
            data = []
            for item in heatmap_data['heatmap'][:20]:
                row = [
                    item['firewall_risk'],
                    item['encryption_risk'],
                    item['update_risk'],
                    item['compliance_risk'],
                    item['overall_risk']
                ]
                data.append(row)
            
            # Create heatmap
            sns.heatmap(data, 
                       xticklabels=categories, 
                       yticklabels=systems,
                       cmap='RdYlGn_r',
                       vmin=0, vmax=1,
                       annot=True,
                       fmt='.2f',
                       cbar_kws={'label': 'Risk Score'})
            
            plt.title('Enterprise Security Risk Heatmap', fontsize=16, fontweight='bold')
            plt.xlabel('Risk Categories', fontsize=12)
            plt.ylabel('Systems', fontsize=12)
            plt.tight_layout()
            
            # Convert to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            log_operation_success("generate_risk_heatmap_visualization")
            return image_base64
            
        except Exception as e:
            log_operation_failure("generate_risk_heatmap_visualization", str(e))
            return ""
    
    def generate_compliance_trend_chart(self) -> str:
        """Generate compliance trend chart"""
        log_operation_start("generate_compliance_trend_chart")
        
        try:
            # Get historical compliance data
            days = 90
            compliance_data = []
            
            for i in range(0, days, 7):  # Weekly data points
                date = datetime.now() - timedelta(days=i)
                # Simulate historical data (in production, fetch from database)
                score = 75 + np.random.normal(0, 5) + (i / days * 10)  # Improving trend
                compliance_data.append({
                    'date': date,
                    'score': min(100, max(0, score))
                })
            
            # Reverse to chronological order
            compliance_data.reverse()
            
            # Create chart
            plt.figure(figsize=(12, 6))
            
            dates = [item['date'] for item in compliance_data]
            scores = [item['score'] for item in compliance_data]
            
            plt.plot(dates, scores, 'b-', linewidth=2, label='Compliance Score')
            plt.fill_between(dates, scores, alpha=0.3)
            
            # Add trend line
            z = np.polyfit(range(len(scores)), scores, 1)
            p = np.poly1d(z)
            plt.plot(dates, p(range(len(scores))), 'r--', linewidth=2, label='Trend')
            
            # Add target line
            plt.axhline(y=85, color='g', linestyle='--', label='Target (85%)')
            
            plt.title('Compliance Score Trend (90 Days)', fontsize=16, fontweight='bold')
            plt.xlabel('Date', fontsize=12)
            plt.ylabel('Compliance Score (%)', fontsize=12)
            plt.legend()
            plt.grid(True, alpha=0.3)
            plt.ylim(0, 100)
            
            # Format x-axis
            plt.gcf().autofmt_xdate()
            
            plt.tight_layout()
            
            # Convert to base64
            buffer = BytesIO()
            plt.savefig(buffer, format='png', dpi=150)
            buffer.seek(0)
            image_base64 = base64.b64encode(buffer.getvalue()).decode()
            plt.close()
            
            log_operation_success("generate_compliance_trend_chart")
            return image_base64
            
        except Exception as e:
            log_operation_failure("generate_compliance_trend_chart", str(e))
            return ""
    
    def generate_executive_report_html(self, summary: Dict[str, Any]) -> str:
        """Generate executive report in HTML format"""
        risk_heatmap = self.generate_risk_heatmap_visualization()
        compliance_chart = self.generate_compliance_trend_chart()
        
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Security Dashboard - Albator</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif; margin: 0; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 36px; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric-value { font-size: 36px; font-weight: bold; margin: 10px 0; }
        .metric-label { color: #666; font-size: 14px; }
        .metric-trend { font-size: 14px; margin-top: 10px; }
        .trend-up { color: #e74c3c; }
        .trend-down { color: #27ae60; }
        
        .section { background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); margin-bottom: 30px; }
        .section h2 { margin-top: 0; color: #2c3e50; border-bottom: 2px solid #ecf0f1; padding-bottom: 10px; }
        
        .risk-badge { display: inline-block; padding: 5px 15px; border-radius: 20px; color: white; font-weight: bold; }
        .risk-low { background: #27ae60; }
        .risk-medium { background: #f39c12; }
        .risk-high { background: #e67e22; }
        .risk-critical { background: #e74c3c; }
        
        .insight-list { list-style: none; padding: 0; }
        .insight-list li { padding: 10px 0; border-bottom: 1px solid #ecf0f1; }
        
        .recommendation { background: #f8f9fa; padding: 15px; margin: 10px 0; border-left: 4px solid #3498db; border-radius: 5px; }
        .recommendation h4 { margin: 0 0 10px 0; color: #2c3e50; }
        .recommendation-meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 10px; font-size: 14px; }
        
        .chart-container { margin: 20px 0; text-align: center; }
        .chart-container img { max-width: 100%; height: auto; border-radius: 5px; }
        
        .kpi-table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        .kpi-table th, .kpi-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ecf0f1; }
        .kpi-table th { background: #f8f9fa; font-weight: 600; }
        
        .footer { text-align: center; padding: 20px; color: #666; font-size: 14px; }
        
        @media print { 
            body { background: white; }
            .section { box-shadow: none; border: 1px solid #ddd; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Executive Security Dashboard</h1>
            <p>Enterprise Security Intelligence Report - {report_date}</p>
        </div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-label">Overall Security Score</div>
                <div class="metric-value">{security_score}%</div>
                <div class="metric-trend">Industry Benchmark: 85%</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Enterprise Risk Level</div>
                <div class="metric-value"><span class="risk-badge risk-{risk_level}">{risk_level_upper}</span></div>
                <div class="metric-trend">Exposure: ${estimated_exposure}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Compliance Rate</div>
                <div class="metric-value">{compliance_rate}%</div>
                <div class="metric-trend">{compliance_trend}</div>
            </div>
            <div class="metric-card">
                <div class="metric-label">Security ROI</div>
                <div class="metric-value">{roi_percentage}%</div>
                <div class="metric-trend">Payback: {payback_months} months</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Key Performance Indicators</h2>
            <table class="kpi-table">
                <tr>
                    <th>Metric</th>
                    <th>Current</th>
                    <th>Target</th>
                    <th>Trend</th>
                    <th>Status</th>
                </tr>
                {kpi_rows}
            </table>
        </div>
        
        <div class="section">
            <h2>Key Insights</h2>
            <ul class="insight-list">
                {insights}
            </ul>
        </div>
        
        <div class="section">
            <h2>Risk Heatmap</h2>
            <div class="chart-container">
                <img src="data:image/png;base64,{risk_heatmap}" alt="Risk Heatmap">
            </div>
        </div>
        
        <div class="section">
            <h2>Compliance Trend</h2>
            <div class="chart-container">
                <img src="data:image/png;base64,{compliance_chart}" alt="Compliance Trend">
            </div>
        </div>
        
        <div class="section">
            <h2>Strategic Recommendations</h2>
            {recommendations}
        </div>
        
        <div class="footer">
            <p>Albator Enterprise Security Platform | Executive Report | Generated: {report_date}</p>
            <p>This report contains confidential security information. Handle with appropriate care.</p>
        </div>
    </div>
</body>
</html>"""
        
        # Format the template with data
        # ... (rest of the method implementation would continue here)
        
        return html_template
