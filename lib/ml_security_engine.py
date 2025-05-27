#!/usr/bin/env python3
"""
Albator Machine Learning Security Engine
Provides ML-based security recommendations and anomaly detection
"""

import os
import sys
import json
import pickle
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import warnings
warnings.filterwarnings('ignore')

# Machine Learning libraries
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.decomposition import PCA
import joblib

# Add lib directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
from logger import get_logger, log_operation_start, log_operation_success, log_operation_failure
from analytics_dashboard import AnalyticsDashboard

@dataclass
class SecurityPrediction:
    """Represents a security prediction"""
    prediction_type: str  # risk_score, compliance_drift, threat_likelihood
    confidence: float
    predicted_value: float
    recommendation: str
    factors: List[Dict[str, Any]]
    timestamp: str

@dataclass
class AnomalyDetection:
    """Represents an anomaly detection result"""
    anomaly_type: str
    severity: str  # low, medium, high, critical
    description: str
    affected_components: List[str]
    confidence: float
    timestamp: str
    remediation: str

class MLSecurityEngine:
    """Machine Learning Security Engine for predictive analytics"""
    
    def __init__(self, model_dir: str = "models"):
        """Initialize the ML Security Engine"""
        self.logger = get_logger("ml_security_engine")
        self.model_dir = model_dir
        self.analytics = AnalyticsDashboard()
        
        # Create model directory if it doesn't exist
        os.makedirs(self.model_dir, exist_ok=True)
        
        # Initialize models
        self.risk_model = None
        self.anomaly_detector = None
        self.compliance_predictor = None
        self.feature_scaler = StandardScaler()
        
        # Load existing models if available
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models if available"""
        try:
            risk_model_path = os.path.join(self.model_dir, "risk_model.pkl")
            if os.path.exists(risk_model_path):
                self.risk_model = joblib.load(risk_model_path)
                self.logger.info("Loaded risk prediction model")
            
            anomaly_model_path = os.path.join(self.model_dir, "anomaly_detector.pkl")
            if os.path.exists(anomaly_model_path):
                self.anomaly_detector = joblib.load(anomaly_model_path)
                self.logger.info("Loaded anomaly detection model")
            
            compliance_model_path = os.path.join(self.model_dir, "compliance_predictor.pkl")
            if os.path.exists(compliance_model_path):
                self.compliance_predictor = joblib.load(compliance_model_path)
                self.logger.info("Loaded compliance prediction model")
            
            scaler_path = os.path.join(self.model_dir, "feature_scaler.pkl")
            if os.path.exists(scaler_path):
                self.feature_scaler = joblib.load(scaler_path)
                self.logger.info("Loaded feature scaler")
                
        except Exception as e:
            self.logger.error(f"Error loading models: {e}")
    
    def _extract_features(self, system_data: Dict[str, Any]) -> np.ndarray:
        """Extract features from system data for ML models"""
        features = []
        
        # Security configuration features
        features.append(1 if system_data.get('firewall_enabled', False) else 0)
        features.append(1 if system_data.get('filevault_enabled', False) else 0)
        features.append(1 if system_data.get('gatekeeper_enabled', False) else 0)
        features.append(1 if system_data.get('sip_enabled', False) else 0)
        
        # Compliance score
        features.append(system_data.get('compliance_score', 0) / 100.0)
        
        # Update metrics
        features.append(1 if system_data.get('automatic_updates_enabled', False) else 0)
        features.append(system_data.get('days_since_last_update', 0) / 30.0)  # Normalize to months
        
        # System metrics
        features.append(system_data.get('failed_login_attempts', 0) / 10.0)  # Normalize
        features.append(system_data.get('unauthorized_app_attempts', 0) / 5.0)  # Normalize
        features.append(system_data.get('network_anomalies', 0) / 10.0)  # Normalize
        
        # Time-based features
        current_hour = datetime.now().hour
        features.append(current_hour / 24.0)  # Normalize hour
        features.append(1 if datetime.now().weekday() >= 5 else 0)  # Weekend indicator
        
        return np.array(features).reshape(1, -1)
    
    def train_risk_model(self, training_data: pd.DataFrame):
        """Train the risk prediction model"""
        log_operation_start("train_risk_model")
        
        try:
            # Prepare features and labels
            feature_columns = [col for col in training_data.columns if col not in ['risk_score', 'timestamp']]
            X = training_data[feature_columns].values
            y = training_data['risk_score'].values
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
            
            # Scale features
            X_train_scaled = self.feature_scaler.fit_transform(X_train)
            X_test_scaled = self.feature_scaler.transform(X_test)
            
            # Train Random Forest model
            self.risk_model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )
            self.risk_model.fit(X_train_scaled, y_train)
            
            # Evaluate model
            y_pred = self.risk_model.predict(X_test_scaled)
            accuracy = accuracy_score(y_test, y_pred)
            
            # Save model
            joblib.dump(self.risk_model, os.path.join(self.model_dir, "risk_model.pkl"))
            joblib.dump(self.feature_scaler, os.path.join(self.model_dir, "feature_scaler.pkl"))
            
            log_operation_success("train_risk_model", {"accuracy": accuracy})
            return accuracy
            
        except Exception as e:
            log_operation_failure("train_risk_model", str(e))
            raise
    
    def train_anomaly_detector(self, normal_behavior_data: pd.DataFrame):
        """Train the anomaly detection model"""
        log_operation_start("train_anomaly_detector")
        
        try:
            # Prepare features
            feature_columns = [col for col in normal_behavior_data.columns if col != 'timestamp']
            X = normal_behavior_data[feature_columns].values
            
            # Scale features
            X_scaled = self.feature_scaler.fit_transform(X)
            
            # Train Isolation Forest for anomaly detection
            self.anomaly_detector = IsolationForest(
                contamination=0.1,  # Expected proportion of anomalies
                random_state=42
            )
            self.anomaly_detector.fit(X_scaled)
            
            # Save model
            joblib.dump(self.anomaly_detector, os.path.join(self.model_dir, "anomaly_detector.pkl"))
            
            log_operation_success("train_anomaly_detector")
            return True
            
        except Exception as e:
            log_operation_failure("train_anomaly_detector", str(e))
            raise
    
    def predict_security_risk(self, system_data: Dict[str, Any]) -> SecurityPrediction:
        """Predict security risk based on current system state"""
        log_operation_start("predict_security_risk")
        
        try:
            # Extract features
            features = self._extract_features(system_data)
            
            # Use pre-trained model or rule-based prediction
            if self.risk_model is not None:
                # Scale features
                features_scaled = self.feature_scaler.transform(features)
                
                # Get prediction and confidence
                risk_score = self.risk_model.predict_proba(features_scaled)[0]
                predicted_class = np.argmax(risk_score)
                confidence = risk_score[predicted_class]
                
                # Map to risk level
                risk_levels = ['low', 'medium', 'high', 'critical']
                risk_level = risk_levels[min(predicted_class, len(risk_levels)-1)]
            else:
                # Rule-based fallback
                risk_score, risk_level, confidence = self._calculate_rule_based_risk(system_data)
            
            # Generate recommendation
            recommendation = self._generate_risk_recommendation(risk_level, system_data)
            
            # Identify contributing factors
            factors = self._identify_risk_factors(system_data)
            
            prediction = SecurityPrediction(
                prediction_type="risk_score",
                confidence=float(confidence),
                predicted_value=float(risk_score) if isinstance(risk_score, (int, float)) else 0.5,
                recommendation=recommendation,
                factors=factors,
                timestamp=datetime.now().isoformat()
            )
            
            log_operation_success("predict_security_risk", {"risk_level": risk_level})
            return prediction
            
        except Exception as e:
            log_operation_failure("predict_security_risk", str(e))
            # Return safe default
            return SecurityPrediction(
                prediction_type="risk_score",
                confidence=0.0,
                predicted_value=0.5,
                recommendation="Unable to predict risk. Please check system configuration.",
                factors=[],
                timestamp=datetime.now().isoformat()
            )
    
    def detect_anomalies(self, system_metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect anomalies in system behavior"""
        log_operation_start("detect_anomalies")
        
        anomalies = []
        
        try:
            # Check for configuration anomalies
            config_anomalies = self._detect_configuration_anomalies(system_metrics)
            anomalies.extend(config_anomalies)
            
            # Check for behavioral anomalies
            if self.anomaly_detector is not None:
                behavioral_anomalies = self._detect_behavioral_anomalies(system_metrics)
                anomalies.extend(behavioral_anomalies)
            
            # Check for compliance drift
            compliance_anomalies = self._detect_compliance_drift(system_metrics)
            anomalies.extend(compliance_anomalies)
            
            log_operation_success("detect_anomalies", {"count": len(anomalies)})
            return anomalies
            
        except Exception as e:
            log_operation_failure("detect_anomalies", str(e))
            return anomalies
    
    def _calculate_rule_based_risk(self, system_data: Dict[str, Any]) -> Tuple[float, str, float]:
        """Calculate risk using rule-based approach"""
        risk_score = 0.0
        
        # Critical security features
        if not system_data.get('firewall_enabled', False):
            risk_score += 0.3
        if not system_data.get('filevault_enabled', False):
            risk_score += 0.3
        if not system_data.get('sip_enabled', False):
            risk_score += 0.2
        if not system_data.get('gatekeeper_enabled', False):
            risk_score += 0.2
        
        # Update status
        days_since_update = system_data.get('days_since_last_update', 0)
        if days_since_update > 30:
            risk_score += 0.1
        if days_since_update > 60:
            risk_score += 0.1
        
        # Failed login attempts
        failed_logins = system_data.get('failed_login_attempts', 0)
        if failed_logins > 5:
            risk_score += 0.1
        if failed_logins > 10:
            risk_score += 0.2
        
        # Determine risk level
        if risk_score <= 0.2:
            risk_level = 'low'
        elif risk_score <= 0.5:
            risk_level = 'medium'
        elif risk_score <= 0.8:
            risk_level = 'high'
        else:
            risk_level = 'critical'
        
        # Confidence based on data completeness
        data_fields = ['firewall_enabled', 'filevault_enabled', 'sip_enabled', 'gatekeeper_enabled']
        available_fields = sum(1 for field in data_fields if field in system_data)
        confidence = available_fields / len(data_fields)
        
        return risk_score, risk_level, confidence
    
    def _generate_risk_recommendation(self, risk_level: str, system_data: Dict[str, Any]) -> str:
        """Generate risk-based recommendations"""
        recommendations = []
        
        if risk_level in ['high', 'critical']:
            # Check critical security features
            if not system_data.get('firewall_enabled', False):
                recommendations.append("Enable Application Firewall immediately")
            if not system_data.get('filevault_enabled', False):
                recommendations.append("Enable FileVault disk encryption")
            if not system_data.get('sip_enabled', False):
                recommendations.append("Enable System Integrity Protection")
            
            # Check updates
            if system_data.get('days_since_last_update', 0) > 30:
                recommendations.append("Install pending security updates")
        
        if not recommendations:
            if risk_level == 'low':
                return "System security is optimal. Continue regular monitoring."
            else:
                return "Review security configurations and apply recommended hardening."
        
        return "URGENT: " + "; ".join(recommendations[:3])  # Top 3 recommendations
    
    def _identify_risk_factors(self, system_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify factors contributing to risk"""
        factors = []
        
        # Security features
        if not system_data.get('firewall_enabled', False):
            factors.append({
                "factor": "Firewall Disabled",
                "impact": "high",
                "weight": 0.3
            })
        
        if not system_data.get('filevault_enabled', False):
            factors.append({
                "factor": "Disk Encryption Disabled",
                "impact": "critical",
                "weight": 0.3
            })
        
        # Updates
        days_since_update = system_data.get('days_since_last_update', 0)
        if days_since_update > 30:
            factors.append({
                "factor": f"No updates for {days_since_update} days",
                "impact": "medium",
                "weight": 0.2
            })
        
        # Failed logins
        failed_logins = system_data.get('failed_login_attempts', 0)
        if failed_logins > 5:
            factors.append({
                "factor": f"{failed_logins} failed login attempts",
                "impact": "medium",
                "weight": 0.1
            })
        
        return factors
    
    def _detect_configuration_anomalies(self, metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect anomalies in configuration"""
        anomalies = []
        
        # Check for unusual configuration changes
        if metrics.get('config_changes_last_hour', 0) > 10:
            anomalies.append(AnomalyDetection(
                anomaly_type="configuration_drift",
                severity="high",
                description="Unusual number of configuration changes detected",
                affected_components=["system_configuration"],
                confidence=0.8,
                timestamp=datetime.now().isoformat(),
                remediation="Review recent configuration changes and verify authorized modifications"
            ))
        
        # Check for disabled security features after being enabled
        if metrics.get('security_features_disabled', 0) > 0:
            anomalies.append(AnomalyDetection(
                anomaly_type="security_regression",
                severity="critical",
                description="Previously enabled security features have been disabled",
                affected_components=["security_settings"],
                confidence=0.95,
                timestamp=datetime.now().isoformat(),
                remediation="Re-enable security features and investigate cause of changes"
            ))
        
        return anomalies
    
    def _detect_behavioral_anomalies(self, metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect behavioral anomalies using ML model"""
        anomalies = []
        
        try:
            # Extract features
            features = self._extract_features(metrics)
            features_scaled = self.feature_scaler.transform(features)
            
            # Predict anomaly
            anomaly_prediction = self.anomaly_detector.predict(features_scaled)
            
            if anomaly_prediction[0] == -1:  # Anomaly detected
                anomaly_score = self.anomaly_detector.score_samples(features_scaled)[0]
                
                # Determine severity based on anomaly score
                if anomaly_score < -0.5:
                    severity = "critical"
                elif anomaly_score < -0.3:
                    severity = "high"
                elif anomaly_score < -0.1:
                    severity = "medium"
                else:
                    severity = "low"
                
                anomalies.append(AnomalyDetection(
                    anomaly_type="behavioral_anomaly",
                    severity=severity,
                    description="System behavior deviates from established baseline",
                    affected_components=["system_behavior"],
                    confidence=abs(anomaly_score),
                    timestamp=datetime.now().isoformat(),
                    remediation="Investigate system activities and check for unauthorized access"
                ))
                
        except Exception as e:
            self.logger.error(f"Error in behavioral anomaly detection: {e}")
        
        return anomalies
    
    def _detect_compliance_drift(self, metrics: Dict[str, Any]) -> List[AnomalyDetection]:
        """Detect compliance drift"""
        anomalies = []
        
        # Check compliance score trend
        current_compliance = metrics.get('compliance_score', 100)
        previous_compliance = metrics.get('previous_compliance_score', 100)
        
        if previous_compliance - current_compliance > 10:
            anomalies.append(AnomalyDetection(
                anomaly_type="compliance_drift",
                severity="high",
                description=f"Compliance score dropped from {previous_compliance}% to {current_compliance}%",
                affected_components=["compliance"],
                confidence=0.9,
                timestamp=datetime.now().isoformat(),
                remediation="Review compliance report and address failed checks"
            ))
        
        return anomalies
    
    def predict_compliance_trend(self, historical_data: pd.DataFrame, days_ahead: int = 30) -> Dict[str, Any]:
        """Predict future compliance trend"""
        log_operation_start("predict_compliance_trend")
        
        try:
            # Simple linear regression for trend prediction
            if len(historical_data) < 7:
                return {
                    "prediction": "insufficient_data",
                    "confidence": 0.0,
                    "message": "Need at least 7 days of historical data"
                }
            
            # Calculate trend
            scores = historical_data['compliance_score'].values
            days = np.arange(len(scores))
            
            # Fit linear trend
            z = np.polyfit(days, scores, 1)
            p = np.poly1d(z)
            
            # Predict future
            future_day = len(scores) + days_ahead
            predicted_score = p(future_day)
            
            # Calculate confidence based on fit quality
            residuals = scores - p(days)
            r_squared = 1 - (np.sum(residuals**2) / np.sum((scores - np.mean(scores))**2))
            
            trend_direction = "improving" if z[0] > 0 else "declining"
            
            result = {
                "prediction": "compliance_trend",
                "predicted_score": float(np.clip(predicted_score, 0, 100)),
                "trend_direction": trend_direction,
                "slope": float(z[0]),
                "confidence": float(max(0, r_squared)),
                "days_ahead": days_ahead,
                "recommendation": self._generate_trend_recommendation(trend_direction, predicted_score)
            }
            
            log_operation_success("predict_compliance_trend", result)
            return result
            
        except Exception as e:
            log_operation_failure("predict_compliance_trend", str(e))
            return {
                "prediction": "error",
                "confidence": 0.0,
                "message": str(e)
            }
    
    def _generate_trend_recommendation(self, trend_direction: str, predicted_score: float) -> str:
        """Generate recommendations based on compliance trend"""
        if trend_direction == "declining":
            if predicted_score < 50:
                return "URGENT: Compliance trending critically low. Immediate remediation required."
            elif predicted_score < 70:
                return "WARNING: Compliance declining. Schedule security review within 7 days."
            else:
                return "Monitor compliance trend. Consider preventive measures."
        else:
            if predicted_score > 90:
                return "Excellent compliance trend. Maintain current security practices."
            else:
                return "Positive trend. Continue security improvements."
    
    def generate_risk_heatmap(self, fleet_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate risk heatmap for fleet visualization"""
        log_operation_start("generate_risk_heatmap")
        
        try:
            heatmap_data = []
            
            for system in fleet_data:
                # Calculate risk scores for different categories
                risk_scores = {
                    "system_id": system.get("system_id", "unknown"),
                    "hostname": system.get("hostname", "unknown"),
                    "firewall_risk": 1.0 if not system.get("firewall_enabled", False) else 0.0,
                    "encryption_risk": 1.0 if not system.get("filevault_enabled", False) else 0.0,
                    "update_risk": min(system.get("days_since_last_update", 0) / 60.0, 1.0),
                    "compliance_risk": 1.0 - (system.get("compliance_score", 0) / 100.0),
                    "overall_risk": 0.0  # Will be calculated
                }
                
                # Calculate overall risk
                risk_values = [
                    risk_scores["firewall_risk"],
                    risk_scores["encryption_risk"],
                    risk_scores["update_risk"],
                    risk_scores["compliance_risk"]
                ]
                risk_scores["overall_risk"] = np.mean(risk_values)
                
                heatmap_data.append(risk_scores)
            
            # Sort by overall risk
            heatmap_data.sort(key=lambda x: x["overall_risk"], reverse=True)
            
            result = {
                "heatmap": heatmap_data,
                "high_risk_systems": [s for s in heatmap_data if s["overall_risk"] > 0.7],
                "statistics": {
                    "total_systems": len(heatmap_data),
                    "high_risk_count": len([s for s in heatmap_data if s["overall_risk"] > 0.7]),
                    "average_risk": np.mean([s["overall_risk"] for s in heatmap_data])
                }
            }
            
            log_operation_success("generate_risk_heatmap", result["statistics"])
            return result
            
        except Exception as e:
            log_operation_failure("generate_risk_heatmap", str(e))
            return {"heatmap": [], "error": str(e)}

def main():
    """Main function for ML security engine"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Albator ML Security Engine")
    parser.add_argument("command", choices=["predict", "train", "analyze", "demo"])
    parser.add_argument("--system-data", help="JSON file with system data")
    parser.add_argument("--training-data", help="CSV file with training data")
    
    args = parser.parse_args()
    
    # Initialize ML engine
    ml_engine = MLSecurityEngine()
    
    if args.command == "predict":
        # Load system data
        if args.system_data:
            with open(args.system_data, 'r') as f:
                system_data = json.load(f)
        else:
            # Demo data
            system_data = {
                "firewall_enabled": True,
                "filevault_enabled": False,
                "gatekeeper_enabled": True,
                "sip_enabled": True,
                "compliance_score": 75,
                "days_since_last_update": 45,
                "failed_login_attempts": 3
            }
        
        # Predict risk
        prediction = ml_engine.predict_security_risk(system_data)
        print("\n🔮 Security Risk Prediction:")
        print(f"   Risk Level: {prediction.predicted_value:.2f}")
        print(f"   Confidence: {prediction.confidence:.2%}")
        print(f"   Recommendation: {prediction.recommendation}")
        print("\n   Risk Factors:")
        for factor in prediction.factors:
            print(f"   - {factor['factor']} (Impact: {factor['impact']})")
        
        # Detect anomalies
        anomalies = ml_engine.detect_anomalies(system_data)
        if anomalies:
            print("\n⚠️  Anomalies Detected:")
            for anomaly in anomalies:
                print(f"   - {anomaly.description}")
                print(f"     Severity: {anomaly.severity}")
                print(f"     Remediation: {anomaly.remediation}")
    
    elif args.command == "demo":
        print("🤖 Albator ML Security Engine Demo")
        print("=" * 50)
        
        # Demo risk prediction
        demo_systems = [
            {
                "name": "Secure System",
                "data": {
                    "firewall_enabled": True,
                    "filevault_enabled": True,
                    "gatekeeper_enabled": True,
                    "sip_enabled": True,
                    "compliance_score": 95,
                    "days_since_last_update": 7,
                    "failed_login_attempts": 0
                }
            },
            {
                "name": "At-Risk System",
                "data": {
                    "firewall_enabled": False,
                    "filevault_enabled": False,
                    "gatekeeper_enabled": True,
                    "sip_enabled": False,
                    "compliance_score": 45,
                    "days_since_last_update": 90,
                    "failed_login_attempts": 15
                }
            }
        ]
        
        for system in demo_systems:
            print(f"\n📊 Analyzing: {system['name']}")
            prediction = ml_engine.predict_security_risk(system['data'])
            print(f"   Risk Score: {prediction.predicted_value:.2f}")
            print(f"   Recommendation: {prediction.recommendation}")

if __name__ == "__main__":
    main()
