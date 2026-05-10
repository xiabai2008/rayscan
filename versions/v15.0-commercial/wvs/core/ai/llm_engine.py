"""AI大模型增强引擎 - v14.0"""
import os
import json
from typing import Dict, List, Any, Optional, AsyncGenerator
from dataclasses import dataclass
from enum import Enum
import asyncio


class LLMProvider(Enum):
    """LLM提供商"""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    LOCAL = "local"


@dataclass
class LLMResponse:
    """LLM响应"""
    content: str
    model: str
    tokens_used: int
    finish_reason: str


class LLMMultiClient:
    """多LLM客户端"""
    
    def __init__(self, providers: Dict[str, Any], fallback_strategy: str = 'hybrid'):
        self.providers = providers
        self.fallback_strategy = fallback_strategy
        self.current_provider = None
        self._init_clients()
    
    def _init_clients(self):
        """初始化客户端"""
        self.clients = {}
        
        # OpenAI
        if 'openai' in self.providers:
            try:
                import openai
                client = openai.AsyncOpenAI(
                    api_key=self.providers['openai']['api_key']
                )
                self.clients['openai'] = {
                    'client': client,
                    'model': self.providers['openai'].get('model', 'gpt-4-turbo'),
                }
            except ImportError:
                pass
        
        # Anthropic
        if 'anthropic' in self.providers:
            try:
                import anthropic
                client = anthropic.AsyncAnthropic(
                    api_key=self.providers['anthropic']['api_key']
                )
                self.clients['anthropic'] = {
                    'client': client,
                    'model': self.providers['anthropic'].get('model', 'claude-3-opus-20240229'),
                }
            except ImportError:
                pass
        
        # Local model (placeholder)
        if 'local' in self.providers:
            self.clients['local'] = {
                'client': None,  # Would load local model here
                'model': self.providers['local'].get('model_path', './models/security-llm'),
            }
    
    async def generate_response(self, prompt: str, 
                                provider: Optional[str] = None,
                                temperature: float = 0.7,
                                max_tokens: int = 2000) -> LLMResponse:
        """生成响应"""
        
        # 尝试指定提供商
        if provider and provider in self.clients:
            return await self._try_generate(provider, prompt, temperature, max_tokens)
        
        # 按优先级尝试
        for prov in ['openai', 'anthropic', 'local']:
            if prov in self.clients:
                try:
                    return await self._try_generate(prov, prompt, temperature, max_tokens)
                except Exception as e:
                    print(f"Provider {prov} failed: {e}")
                    continue
        
        raise Exception("All LLM providers failed")
    
    async def _try_generate(self, provider: str, prompt: str,
                           temperature: float, max_tokens: int) -> LLMResponse:
        """尝试使用指定提供商生成"""
        config = self.clients[provider]
        
        if provider == 'openai':
            response = await config['client'].chat.completions.create(
                model=config['model'],
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
            )
            return LLMResponse(
                content=response.choices[0].message.content,
                model=config['model'],
                tokens_used=response.usage.total_tokens,
                finish_reason=response.choices[0].finish_reason,
            )
        
        elif provider == 'anthropic':
            response = await config['client'].messages.create(
                model=config['model'],
                max_tokens=max_tokens,
                temperature=temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return LLMResponse(
                content=response.content[0].text,
                model=config['model'],
                tokens_used=response.usage.input_tokens + response.usage.output_tokens,
                finish_reason=response.stop_reason,
            )
        
        elif provider == 'local':
            # 本地模型占位符
            return LLMResponse(
                content="Local model response placeholder",
                model=config['model'],
                tokens_used=0,
                finish_reason="stop",
            )
        
        raise ValueError(f"Unknown provider: {provider}")


class LLMEnhancedEngine:
    """LLM增强引擎"""
    
    def __init__(self):
        self.llm_client = self._initialize_llm_client()
        self.prompt_templates = self._load_prompt_templates()
        self.knowledge_base = self._load_security_knowledge_base()
    
    def _initialize_llm_client(self) -> LLMMultiClient:
        """初始化LLM客户端"""
        providers = {
            'openai': {
                'api_key': os.getenv('OPENAI_API_KEY', ''),
                'model': 'gpt-4-turbo',
            },
            'anthropic': {
                'api_key': os.getenv('ANTHROPIC_API_KEY', ''),
                'model': 'claude-3-opus-20240229',
            },
            'local': {
                'model_path': './models/security-llm-7b',
            },
        }
        
        # 过滤掉没有API key的提供商
        providers = {k: v for k, v in providers.items() 
                    if k == 'local' or v.get('api_key')}
        
        return LLMMultiClient(providers, fallback_strategy='hybrid')
    
    def _load_prompt_templates(self) -> Dict[str, str]:
        """加载提示模板"""
        return {
            'vulnerability_analysis': """你是一位资深安全专家。请分析以下漏洞并提供深度分析：

漏洞类型: {vulnerability_type}
证据: {evidence}
上下文: {context}

请提供以下分析（JSON格式）：
{{
    "analysis": "详细技术分析",
    "exploit_likelihood": "高/中/低 - 评估被利用的可能性",
    "business_impact": "对业务的潜在影响",
    "remediation_strategy": "具体的修复策略",
    "similar_incidents": "类似的历史安全事件"
}}
""",
            'executive_summary': """你是一位安全顾问。请为高管生成以下扫描结果的执行摘要：

扫描结果: {scan_results}
业务背景: {business_context}
风险优先级: {risk_priorities}

请生成一份简洁的执行摘要（2-3段），包括：
1. 整体安全态势
2. 最关键的风险
3. 建议的优先行动
""",
            'technical_report': """你是一位技术安全专家。请生成详细的技术报告：

扫描结果: {scan_results}
修复详情: {remediation_details}
代码示例: {code_examples}

请提供：
1. 技术漏洞分析
2. 详细的修复步骤
3. 代码修复示例
4. 验证方法
""",
            'risk_prediction': """你是一位威胁情报分析师。基于以下数据预测安全风险：

历史漏洞: {historical_vulnerabilities}
威胁情报: {threat_intel}
当前扫描结果: {current_scan_results}
行业背景: {industry_context}

请预测（JSON格式）：
{{
    "high_risk_areas": ["高风险区域列表"],
    "emerging_threats": ["新兴威胁列表"],
    "remediation_priority": ["修复优先级建议"],
    "timeline_prediction": "风险时间线预测"
}}
""",
        }
    
    def _load_security_knowledge_base(self) -> Dict[str, Any]:
        """加载安全知识库"""
        return {
            'cve_database': {},  # 可加载CVE数据
            'exploit_patterns': {},
            'mitigation_strategies': {
                'xss': '输入验证 + 输出编码 + CSP',
                'sqli': '参数化查询 + ORM',
                'csrf': 'Token验证 + SameSite Cookie',
            },
        }
    
    def get_relevant_knowledge(self, vulnerability_type: str) -> str:
        """获取相关知识"""
        return self.knowledge_base['mitigation_strategies'].get(
            vulnerability_type.lower(), 
            '参考OWASP指南'
        )
    
    async def analyze_vulnerability_with_llm(self, 
                                             vulnerability_data: Dict) -> Dict[str, Any]:
        """使用LLM深度分析漏洞"""
        prompt = self.prompt_templates['vulnerability_analysis'].format(
            vulnerability_type=vulnerability_data.get('type', 'Unknown'),
            evidence=json.dumps(vulnerability_data.get('evidence', {}), indent=2),
            context=json.dumps(vulnerability_data.get('context', {}), indent=2),
            knowledge_base=self.get_relevant_knowledge(vulnerability_data.get('type', '')),
        )
        
        try:
            response = await self.llm_client.generate_response(prompt)
            
            # 尝试解析JSON响应
            try:
                analysis = json.loads(response.content)
            except json.JSONDecodeError:
                # 如果不是JSON，包装成结构化格式
                analysis = {
                    'analysis': response.content,
                    'exploit_likelihood': 'unknown',
                    'business_impact': 'unknown',
                    'remediation_strategy': 'unknown',
                    'similar_incidents': 'unknown',
                }
            
            return {
                'analysis': analysis.get('analysis', response.content),
                'exploit_likelihood': analysis.get('exploit_likelihood', 'unknown'),
                'business_impact': analysis.get('business_impact', 'unknown'),
                'remediation_strategy': analysis.get('remediation_strategy', 'unknown'),
                'similar_incidents': analysis.get('similar_incidents', 'unknown'),
                'tokens_used': response.tokens_used,
                'model': response.model,
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'analysis': 'LLM分析失败，使用规则引擎分析',
                'exploit_likelihood': 'medium',
                'business_impact': 'unknown',
            }
    
    async def generate_intelligent_report(self, 
                                          scan_results: Dict,
                                          audience: str = 'executive') -> str:
        """智能报告生成"""
        if audience == 'executive':
            prompt = self.prompt_templates['executive_summary'].format(
                scan_results=json.dumps(scan_results, indent=2),
                business_context=self._get_business_context(),
                risk_priorities=self._get_risk_priorities(scan_results),
            )
        elif audience == 'technical':
            prompt = self.prompt_templates['technical_report'].format(
                scan_results=json.dumps(scan_results, indent=2),
                remediation_details=self._get_remediation_details(scan_results),
                code_examples=self._get_code_examples(scan_results),
            )
        else:
            return f"Unknown audience: {audience}"
        
        try:
            response = await self.llm_client.generate_response(prompt)
            return response.content
        except Exception as e:
            return f"Report generation failed: {str(e)}"
    
    async def predict_security_risks(self,
                                     historical_data: Dict,
                                     current_scan: Dict) -> Dict[str, Any]:
        """预测安全风险"""
        prompt = self.prompt_templates['risk_prediction'].format(
            historical_vulnerabilities=json.dumps(historical_data.get('vulnerabilities', []), indent=2),
            threat_intel=json.dumps(historical_data.get('threat_intel', {}), indent=2),
            current_scan_results=json.dumps(current_scan, indent=2),
            industry_context=self._get_industry_context(),
        )
        
        try:
            response = await self.llm_client.generate_response(prompt)
            
            try:
                prediction = json.loads(response.content)
            except json.JSONDecodeError:
                prediction = {
                    'high_risk_areas': ['解析失败'],
                    'emerging_threats': ['解析失败'],
                    'remediation_priority': ['解析失败'],
                    'timeline_prediction': '解析失败',
                }
            
            return {
                'high_risk_areas': prediction.get('high_risk_areas', []),
                'emerging_threats': prediction.get('emerging_threats', []),
                'remediation_priority': prediction.get('remediation_priority', []),
                'timeline_prediction': prediction.get('timeline_prediction', ''),
                'tokens_used': response.tokens_used,
                'model': response.model,
            }
            
        except Exception as e:
            return {
                'error': str(e),
                'high_risk_areas': [],
                'emerging_threats': [],
                'remediation_priority': [],
            }
    
    def _get_business_context(self) -> str:
        """获取业务上下文"""
        return "Web应用安全评估"
    
    def _get_risk_priorities(self, scan_results: Dict) -> str:
        """获取风险优先级"""
        critical = scan_results.get('critical', 0)
        high = scan_results.get('high', 0)
        return f"Critical: {critical}, High: {high}"
    
    def _get_remediation_details(self, scan_results: Dict) -> str:
        """获取修复详情"""
        return "参考OWASP修复指南"
    
    def _get_code_examples(self, scan_results: Dict) -> str:
        """获取代码示例"""
        return "参考安全编码规范"
    
    def _get_industry_context(self) -> str:
        """获取行业上下文"""
        return "通用Web应用"


class AIEnhancedScanner:
    """AI增强扫描器"""
    
    def __init__(self):
        self.llm_engine = LLMEnhancedEngine()
    
    async def analyze_scan_results(self, scan_results: Dict) -> Dict[str, Any]:
        """分析扫描结果"""
        enhanced_results = {
            'original_results': scan_results,
            'llm_analysis': {},
            'risk_prediction': {},
        }
        
        # 对每个高危漏洞进行LLM分析
        vulnerabilities = scan_results.get('vulnerabilities', [])
        high_risk_vulns = [v for v in vulnerabilities 
                          if v.get('severity') in ['critical', 'high']]
        
        for vuln in high_risk_vulns[:5]:  # 限制分析数量
            analysis = await self.llm_engine.analyze_vulnerability_with_llm(vuln)
            enhanced_results['llm_analysis'][vuln.get('id', 'unknown')] = analysis
        
        # 生成风险预测
        historical_data = {
            'vulnerabilities': vulnerabilities,
            'threat_intel': {},
        }
        prediction = await self.llm_engine.predict_security_risks(
            historical_data, scan_results
        )
        enhanced_results['risk_prediction'] = prediction
        
        return enhanced_results
    
    async def generate_report(self, scan_results: Dict, 
                              audience: str = 'executive') -> str:
        """生成智能报告"""
        return await self.llm_engine.generate_intelligent_report(
            scan_results, audience
        )
