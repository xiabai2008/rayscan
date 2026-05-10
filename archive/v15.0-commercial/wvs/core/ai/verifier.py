"""AI漏洞验证模块 - 基于机器学习的漏洞验证"""
import numpy as np
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import hashlib
import json


@dataclass
class AIVerificationResult:
    """AI验证结果"""
    is_vulnerable: bool
    confidence: float
    explanation: str
    features: Dict[str, float]


class AIVulnerabilityVerifier:
    """AI漏洞验证器"""
    
    def __init__(self, model_path: str = None):
        self.model_path = model_path or "models/vulnerability_classifier.pkl"
        self.feature_names = [
            'response_time_variance',
            'error_pattern_frequency',
            'payload_reflection_depth', 
            'context_sensitivity_score',
            'historical_false_positive_rate'
        ]
        self.model = None
        self._load_model()
        
        # 历史误报率缓存
        self.historical_fpr: Dict[str, float] = {}
    
    def _load_model(self):
        """加载机器学习模型"""
        try:
            import joblib
            self.model = joblib.load(self.model_path)
        except (ImportError, FileNotFoundError):
            # 如果模型不存在，使用简单的规则引擎
            self.model = None
    
    def extract_features(self, scan_result: Dict) -> Dict[str, float]:
        """提取特征向量"""
        features = {}
        
        # 响应时间方差
        response_times = scan_result.get('response_times', [])
        if response_times:
            features['response_time_variance'] = float(np.var(response_times))
        else:
            features['response_time_variance'] = 0.0
        
        # 错误模式频率
        errors = scan_result.get('error_patterns', [])
        total_requests = max(len(response_times), 1)
        features['error_pattern_frequency'] = len(errors) / total_requests
        
        # Payload反射深度
        payload_reflection = scan_result.get('payload_reflection', {})
        features['payload_reflection_depth'] = float(payload_reflection.get('depth', 0))
        
        # 上下文敏感度评分
        features['context_sensitivity_score'] = self._calculate_context_score(scan_result)
        
        # 历史误报率
        target = scan_result.get('target', '')
        features['historical_false_positive_rate'] = self._get_historical_fpr(target)
        
        return features
    
    def _calculate_context_score(self, scan_result: Dict) -> float:
        """计算上下文敏感度评分"""
        score = 0.0
        
        # 检查响应中是否包含敏感上下文
        response = scan_result.get('response', '')
        
        # SQL错误上下文
        sql_patterns = [
            r'sql syntax', r'mysql_fetch', r'pg_query',
            r'oracle error', r'sqlite_query'
        ]
        for pattern in sql_patterns:
            if pattern in response.lower():
                score += 0.2
        
        # XSS上下文
        xss_patterns = [
            r'<script', r'javascript:', r'onerror=',
            r'onload=', r'eval\(', r'document\.cookie'
        ]
        for pattern in xss_patterns:
            if pattern in response.lower():
                score += 0.15
        
        # 命令注入上下文
        cmd_patterns = [
            r'system\(', r'exec\(', r'eval\(',
            r'shell_exec', r'passthru'
        ]
        for pattern in cmd_patterns:
            if pattern in response.lower():
                score += 0.25
        
        return min(score, 1.0)
    
    def _get_historical_fpr(self, target: str) -> float:
        """获取目标的历史误报率"""
        target_hash = hashlib.md5(target.encode()).hexdigest()
        return self.historical_fpr.get(target_hash, 0.1)
    
    def update_historical_fpr(self, target: str, is_false_positive: bool):
        """更新历史误报率"""
        target_hash = hashlib.md5(target.encode()).hexdigest()
        current_fpr = self.historical_fpr.get(target_hash, 0.1)
        
        # 指数移动平均
        alpha = 0.1
        if is_false_positive:
            self.historical_fpr[target_hash] = current_fpr * (1 - alpha) + alpha
        else:
            self.historical_fpr[target_hash] = current_fpr * (1 - alpha)
    
    def verify(self, scan_result: Dict) -> AIVerificationResult:
        """验证漏洞"""
        features = self.extract_features(scan_result)
        feature_vector = [features[name] for name in self.feature_names]
        
        if self.model:
            # 使用机器学习模型
            try:
                prediction_proba = self.model.predict_proba([feature_vector])[0]
                is_vulnerable = prediction_proba[1] > 0.85
                confidence = prediction_proba[1] if is_vulnerable else prediction_proba[0]
            except Exception:
                # 模型预测失败，使用规则引擎
                is_vulnerable, confidence = self._rule_based_verify(features)
        else:
            # 使用规则引擎
            is_vulnerable, confidence = self._rule_based_verify(features)
        
        explanation = self._generate_explanation(features, is_vulnerable)
        
        return AIVerificationResult(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            explanation=explanation,
            features=features
        )
    
    def _rule_based_verify(self, features: Dict[str, float]) -> tuple:
        """基于规则的验证（备用方案）"""
        score = 0.0
        
        # 响应时间方差大 -> 可能存在时间盲注
        if features['response_time_variance'] > 1000:
            score += 0.3
        
        # 错误模式频繁 -> 可能存在漏洞
        if features['error_pattern_frequency'] > 0.3:
            score += 0.25
        
        # Payload反射深 -> 可能存在XSS
        if features['payload_reflection_depth'] > 2:
            score += 0.2
        
        # 上下文敏感度高 -> 可能存在漏洞
        if features['context_sensitivity_score'] > 0.5:
            score += 0.15
        
        # 历史误报率低 -> 更可信
        if features['historical_false_positive_rate'] < 0.05:
            score += 0.1
        
        is_vulnerable = score > 0.6
        confidence = min(score * 1.2, 0.95) if is_vulnerable else 1 - score
        
        return is_vulnerable, confidence
    
    def _generate_explanation(self, features: Dict[str, float], is_vulnerable: bool) -> str:
        """生成解释说明"""
        if not is_vulnerable:
            return "基于多维度特征分析，未检测到明显漏洞特征"
        
        explanations = []
        
        if features['response_time_variance'] > 1000:
            explanations.append("检测到异常响应时间波动，可能存在时间延迟注入")
        
        if features['error_pattern_frequency'] > 0.3:
            explanations.append("错误模式出现频率高，符合漏洞特征")
        
        if features['payload_reflection_depth'] > 2:
            explanations.append("Payload在响应中深度反射，存在XSS风险")
        
        if features['context_sensitivity_score'] > 0.5:
            explanations.append("响应中包含敏感上下文，可能存在安全问题")
        
        if features['historical_false_positive_rate'] < 0.05:
            explanations.append("该目标历史误报率低，结果可信度高")
        
        return "; ".join(explanations) if explanations else "基于多维度特征分析确认存在漏洞"


class FeatureExtractor:
    """特征提取器"""
    
    @staticmethod
    def extract_response_features(response: str, payload: str) -> Dict[str, Any]:
        """提取响应特征"""
        features = {
            'response_length': len(response),
            'payload_reflection_count': response.count(payload),
            'html_tags_count': response.count('<'),
            'script_tags_count': response.lower().count('<script'),
            'error_keywords_count': 0,
            'sensitive_keywords_count': 0,
        }
        
        # 错误关键词
        error_keywords = ['error', 'exception', 'warning', 'fatal', 'syntax']
        for keyword in error_keywords:
            features['error_keywords_count'] += response.lower().count(keyword)
        
        # 敏感关键词
        sensitive_keywords = ['password', 'secret', 'token', 'key', 'admin']
        for keyword in sensitive_keywords:
            features['sensitive_keywords_count'] += response.lower().count(keyword)
        
        return features
    
    @staticmethod
    def extract_timing_features(response_times: List[float]) -> Dict[str, float]:
        """提取时间特征"""
        if not response_times:
            return {'mean': 0, 'variance': 0, 'min': 0, 'max': 0}
        
        return {
            'mean': float(np.mean(response_times)),
            'variance': float(np.var(response_times)),
            'min': float(np.min(response_times)),
            'max': float(np.max(response_times)),
        }


class ModelLoader:
    """模型加载器"""
    
    @staticmethod
    def load_model(model_path: str):
        """加载模型"""
        try:
            import joblib
            return joblib.load(model_path)
        except ImportError:
            print("Warning: joblib not installed, using rule-based verification")
            return None
        except FileNotFoundError:
            print(f"Warning: Model file not found: {model_path}")
            return None
    
    @staticmethod
    def save_model(model, model_path: str):
        """保存模型"""
        try:
            import joblib
            joblib.dump(model, model_path)
            return True
        except Exception as e:
            print(f"Error saving model: {e}")
            return False
    
    @staticmethod
    def create_dummy_model():
        """创建示例模型（用于测试）"""
        try:
            from sklearn.ensemble import RandomForestClassifier
            import numpy as np
            
            # 创建随机数据训练示例模型
            X = np.random.rand(100, 5)
            y = np.random.randint(0, 2, 100)
            
            model = RandomForestClassifier(n_estimators=10)
            model.fit(X, y)
            
            return model
        except ImportError:
            return None
