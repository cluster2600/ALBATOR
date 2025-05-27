#!/usr/bin/env python3
"""
Executive Dashboard Helper Methods
Provides utility functions for the executive dashboard
"""

import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

class ExecutiveDashboardHelpers:
    """Helper methods for ExecutiveDashboard class"""
    
    @staticmethod
    def _calculate_percentage_change(previous: float, current: float) -> float:
        """Calculate percentage change between two values"""
        if previous == 0:
            return 100.0 if current > 0 else 0.0
        return ((current - previous) / previous) * 100
    
    @staticmethod
    def _forecast_value(current: float, previous: float, days_ahead: int = 30) -> float:
        """Simple linear forecast based on current trend"""
        if previous == 0:
            return current
        
        # Calculate daily change rate
        daily_change = (current - previous) / 30  # Assuming 30-day period
        
        # Project forward
        forecast = current + (daily_change * days_ahead)
        
        # Ensure non-negative
        return max(0, forecast)
    
    @staticmethod
    def _get_incident_count(days: int, offset_days: int = 0) -> int:
        """Get incident count for a period (simulated for demo)"""
        # In production, this would query the incident database
        # For demo, return simulated data
        base_count = 3
        if offset_days > 0:
            # Historical data tends to be slightly higher
            base_count = 5
        
        # Add some randomness
        variation = np.random.randint(-1, 2)
        return max(0, base_count + variation)
    
    @staticmethod
    def _calculate_mttr(days: int, offset_days: int = 0) -> float:
        """Calculate mean time to remediate in hours"""
        # In production, query incident resolution times
        base_mttr = 3.5
        if offset_days > 0:
            # Historical MTTR was higher
            base_mttr = 5.0
        
        # Add some variation
        variation = np.random.uniform(-0.5, 0.5)
        return max(0.5, base_mttr + variation)
    
    @staticmethod
    def _calculate_exposure_window(days: int, offset_days: int = 0) -> float:
        """Calculate average vulnerability exposure window in days"""
        # In production, calculate from patch deployment data
        base_exposure = 10
        if offset_days > 0:
            # Historical exposure was higher
            base_exposure = 15
        
        # Add variation
        variation = np.random.uniform(-2, 2)
        return max(1, base_exposure + variation)
    
    @staticmethod
    def _get_system_security_data(host_id: str) -> Dict[str, Any]:
        """Get security data for a specific system"""
        # In production, query system database
        # For demo, return simulated data
        return {
            "system_id": host_id,
            "hostname": f"mac-{host_id[-4:]}",
            "firewall_enabled": np.random.random() > 0.2,  # 80% have firewall
            "filevault_enabled": np.random.random() > 0.3,  # 70% have encryption
            "gatekeeper_enabled": np.random.random() > 0.1,  # 90% have gatekeeper
            "sip_enabled": np.random.random() > 0.05,  # 95% have SIP
            "compliance_score": np.random.randint(60, 95),
            "days_since_last_update": np.random.randint(0, 60),
            "failed_login_attempts": np.random.randint(0, 10),
            "automatic_updates_enabled": np.random.random() > 0.3
        }
    
    @staticmethod
    def _get_historical_risk_scores(days: int) -> List[float]:
        """Get historical risk scores"""
        # In production, query from analytics database
        scores = []
        for i in range(days):
            # Simulate improving trend
            base_score = 0.6 - (i / days * 0.2)
            variation = np.random.uniform(-0.05, 0.05)
            scores.append(max(0.1, min(0.9, base_score + variation)))
        return scores
    
    @staticmethod
    def _generate_mitigation_priorities(top_risks: List[Dict[str, Any]]) -> List[str]:
        """Generate mitigation priorities from top risks"""
        priorities = []
        
        # Analyze risk factors
        factor_counts = {}
        for risk in top_risks:
            for factor in risk.get('factors', []):
                factor_name = factor['factor']
                if factor_name not in factor_counts:
                    factor_counts[factor_name] = 0
                factor_counts[factor_name] += 1
        
        # Sort by frequency
        sorted_factors = sorted(factor_counts.items(), key=lambda x: x[1], reverse=True)
        
        # Generate priorities
        for factor, count in sorted_factors[:5]:
            if "Firewall" in factor:
                priorities.append("Deploy enterprise firewall configuration")
            elif "Encryption" in factor:
                priorities.append("Implement full-disk encryption fleet-wide")
            elif "updates" in factor.lower():
                priorities.append("Establish automated patch management")
            elif "login" in factor:
                priorities.append("Strengthen authentication policies")
            else:
                priorities.append(f"Address {factor}")
        
        return priorities
    
    @staticmethod
    def _estimate_financial_exposure(risk_score: float, system_count: int) -> float:
        """Estimate financial exposure based on risk"""
        # Industry average cost per system breach
        cost_per_breach = 50000
        
        # Probability of breach based on risk score
        breach_probability = risk_score
        
        # Expected number of breaches
        expected_breaches = system_count * breach_probability * 0.1  # 10% annual rate
        
        # Total exposure
        exposure = expected_breaches * cost_per_breach
        
        # Add indirect costs (reputation, productivity loss)
        indirect_multiplier = 2.5
        total_exposure = exposure * indirect_multiplier
        
        return round(total_exposure, -3)  # Round to nearest thousand
    
    @staticmethod
    def _calculate_compliance_trend() -> str:
        """Calculate compliance trend direction"""
        # In production, analyze historical data
        # For demo, return simulated trend
        trends = ["improving", "stable", "declining"]
        weights = [0.6, 0.3, 0.1]  # Favor improving trend
        return np.random.choice(trends, p=weights)
    
    @staticmethod
    def _calculate_fleet_health_score() -> float:
        """Calculate overall fleet health score"""
        # In production, aggregate multiple metrics
        # For demo, return simulated score
        base_score = 75
        variation = np.random.uniform(-5, 10)
        return min(100, max(0, base_score + variation))
    
    @staticmethod
    def _calculate_security_grade(score: float) -> str:
        """Calculate letter grade from security score"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    @staticmethod
    def _compare_to_industry_benchmarks(kpis: List[Any]) -> Dict[str, Any]:
        """Compare KPIs to industry benchmarks"""
        comparison = {
            "better_than_industry": 0,
            "at_industry_level": 0,
            "below_industry": 0,
            "overall_position": ""
        }
        
        for kpi in kpis:
            if kpi.status == "on_track":
                if kpi.current_value < kpi.target_value * 0.9:
                    comparison["better_than_industry"] += 1
                else:
                    comparison["at_industry_level"] += 1
            else:
                comparison["below_industry"] += 1
        
        # Determine overall position
        total = len(kpis)
        if comparison["better_than_industry"] > total / 2:
            comparison["overall_position"] = "Industry Leader"
        elif comparison["below_industry"] > total / 2:
            comparison["overall_position"] = "Below Industry Average"
        else:
            comparison["overall_position"] = "Industry Average"
        
        return comparison
