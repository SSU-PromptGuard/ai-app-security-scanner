# **1\. schema의 목적과 출력 단위 결정**

\*\* rule metadata와 finding schema 차이   
\=\> rule metadata는 rule 자체의 고정정보이지만 finding은 실제 코드에서 탐지된 결과라는 점에서 다르다.   
rule metadata \= 어떤 rule인가?  
finding schema \= 어느 파일의 어느 줄에서 실제로 무엇을 탐지했는가?

1) 최종 출력 구조(scan 결과 전체를 감싸는 wrapper 방식)   
   {  
     "target": "uploaded.py",  
     "findings": \[  
       {  
         "rule\_id": "LLM05\_LLM\_OUTPUT\_TO\_SHELL",  
         "category": "LLM05:2025 Improper Output Handling",  
         "status": "vulnerable",  
         "severity": "critical",  
         "file": "uploaded.py",  
         "line": 12,  
         "source\_kind": "llm\_output",  
         "source": "llm.invoke",  
         "sink\_kind": "shell\_execution",  
         "sink": "os.system",  
         "flow": "llm.invoke(...) \-\> cmd \-\> os.system(cmd)",  
         "confidence": 0.9,  
         "evidence": "os.system(cmd)"  
       }  
     \],  
     "summary": {  
       "total\_findings": 1  
     }  
   }

\*\* 이때 status가 safe인 경우는 finding으로 만들지 않는다.   
{  
  "target": "safe\_sample.py",  
  "findings": \[\],  
  "summary": {  
    "total\_findings": 0  
  }  
}

# **2\. Finding 최소 필드 결정**

\<Finding Schema\>  
{  
  "finding\_id": "LLM05\_LLM\_OUTPUT\_TO\_SHELL:sample.py:8:os.system",  
  "rule\_id": "LLM05\_LLM\_OUTPUT\_TO\_SHELL",  
  "category": "LLM05:2025 Improper Output Handling",  
  "status": "vulnerable",  
  "severity": "critical",  
  "file": "sample.py",  
  "line": 8,  
  "source\_kind": "llm\_output",  
  "source": "llm.invoke",  
  "sink\_kind": "shell\_execution",  
  "sink": "os.system",  
  "flow": "llm.invoke(...) \-\> cmd \-\> os.system(cmd)",  
  "evidence": "os.system(cmd)",  
  "confidence": 0.9  
}

| 필드 | 역할 | 예시 |
| ----- | ----- | ----- |
| `finding_id` | finding 고유 식별자 | `LLM05_LLM_OUTPUT_TO_SHELL:sample.py:8:os.system` |
| `rule_id` | 어떤 rule에 걸렸는지 | `LLM05_LLM_OUTPUT_TO_SHELL` |
| `category` | OWASP category | `LLM05:2025 Improper Output Handling` |
| `status` | 취약 흐름인지 위험 패턴인지 | `vulnerable` |
| `severity` | 영향도 | `critical` |
| `file` | 탐지된 파일 | `sample.py` |
| `line` | 대표 탐지 line | `8` |
| `source_kind` | source family | `llm_output` |
| `source` | 실제 source 표현 | `llm.invoke` |
| `sink_kind` | sink family | `shell_execution` |
| `sink` | 실제 sink 표현 | `os.system` |
| `flow` | source→sink 흐름 요약 | `llm.invoke(...) -> cmd -> os.system(cmd)` |
| `evidence` | 실제 코드 근거 | `os.system(cmd)` |
| `confidence` | 탐지 근거 확신도 | `0.9` |

# **3\. ScanResult wrapper 필드 결정**

\=\> scanner가 항상 finding list만 반환하면 어떤 파일을 분석했는지, 총 finding은 몇 개인지, category별 개수는 몇 개 인지 등등을 UI에서 따로 관리해야 하므로 ScanResult라는 wrapper를 두는 방식으로 구성

\<ScanResult Schema\>  
{  
  "target": "uploaded.py",  
  "ok": true,  
  "parse\_error": null,  
  "findings": \[\],  
  "summary": {}  
}

| 필드 | 의미 | 예시 |
| ----- | ----- | ----- |
| `target` | 분석 대상 파일명 또는 입력 이름 | `uploaded.py` |
| `ok` | 분석 성공 여부 | `true` |
| `parse_error` | Python AST parse 실패 시 에러 메시지 | `null` |
| `findings` | Finding 객체 리스트 | `[...]` |
| `summary` | finding 요약 통계 | `{...}` |

\*\* parse\_error는 사용자가 python 문법이 깨진 코드를 넣었을 때 scanner가 죽지 않고 ScanResult로 에러를 반환하기 위함임. 

\<정상 스캔 결과 예시\>  
{  
  "target": "samples/dev/llm05\_shell.py",  
  "ok": true,  
  "parse\_error": null,  
  "findings": \[  
    {  
      "finding\_id": "LLM05\_LLM\_OUTPUT\_TO\_SHELL:samples/dev/llm05\_shell.py:8:os.system",  
      "rule\_id": "LLM05\_LLM\_OUTPUT\_TO\_SHELL",  
      "category": "LLM05:2025 Improper Output Handling",  
      "status": "vulnerable",  
      "severity": "critical",  
      "file": "samples/dev/llm05\_shell.py",  
      "line": 8,  
      "source\_kind": "llm\_output",  
      "source": "llm.invoke",  
      "sink\_kind": "shell\_execution",  
      "sink": "os.system",  
      "flow": "llm.invoke(...) \-\> cmd \-\> os.system(cmd)",  
      "evidence": "os.system(cmd)",  
      "confidence": 0.9  
    }  
  \],  
  "summary": {  
    "total\_findings": 1,  
    "by\_severity": {  
      "critical": 1,  
      "high": 0,  
      "medium": 0,  
      "low": 0  
    },  
    "by\_status": {  
      "vulnerable": 1,  
      "risky": 0  
    },  
    "by\_category": {  
      "LLM05:2025 Improper Output Handling": 1  
    }  
  }  
}

\<safe 예시\>  
{  
  "target": "samples/dev/safe\_llm\_call.py",  
  "ok": true,  
  "parse\_error": null,  
  "findings": \[\],  
  "summary": {  
    "total\_findings": 0,  
    "by\_severity": {  
      "critical": 0,  
      "high": 0,  
      "medium": 0,  
      "low": 0  
    },  
    "by\_status": {  
      "vulnerable": 0,  
      "risky": 0  
    },  
    "by\_category": {}  
  }  
}

# **4\. result\_schema.json 최종 초안 확정**

{  
  "$schema": "https://json-schema.org/draft/2020-12/schema",  
  "title": "PromptGuard Lite Layer A Scan Result Schema",  
  "type": "object",  
  "required": \["target", "ok", "parse\_error", "findings", "summary"\],  
  "properties": {  
    "target": {  
      "type": "string",  
      "description": "Scanned file path, uploaded filename, or input name."  
    },  
    "ok": {  
      "type": "boolean",  
      "description": "Whether parsing and scanning completed successfully."  
    },  
    "parse\_error": {  
      "type": \["string", "null"\],  
      "description": "Python parse error message. Null if parsing succeeded."  
    },  
    "findings": {  
      "type": "array",  
      "description": "List of detected vulnerable or risky patterns. Safe files have an empty findings list.",  
      "items": {  
        "$ref": "\#/$defs/Finding"  
      }  
    },  
    "summary": {  
      "$ref": "\#/$defs/Summary"  
    }  
  },  
  "$defs": {  
    "Finding": {  
      "type": "object",  
      "required": \[  
        "finding\_id",  
        "rule\_id",  
        "category",  
        "status",  
        "severity",  
        "file",  
        "line",  
        "source\_kind",  
        "source",  
        "sink\_kind",  
        "sink",  
        "flow",  
        "evidence",  
        "confidence"  
      \],  
      "properties": {  
        "finding\_id": {  
          "type": "string",  
          "description": "Unique identifier for a finding, usually generated from rule\_id, file, line, and sink."  
        },  
        "rule\_id": {  
          "type": "string",  
          "description": "Atomic rule identifier."  
        },  
        "category": {  
          "type": "string",  
          "enum": \[  
            "LLM01:2025 Prompt Injection",  
            "LLM02:2025 Sensitive Information Disclosure",  
            "LLM03:2025 Supply Chain",  
            "LLM05:2025 Improper Output Handling",  
            "LLM06:2025 Excessive Agency",  
            "LLM07:2025 System Prompt Leakage"  
          \],  
          "description": "OWASP LLM 2025 category."  
        },  
        "status": {  
          "type": "string",  
          "enum": \["vulnerable", "risky"\],  
          "description": "Interpretation of the detected atomic pattern. Safe is represented by an empty findings list."  
        },  
        "severity": {  
          "type": "string",  
          "enum": \["critical", "high", "medium", "low"\],  
          "description": "Expected impact if the detected pattern is exploited or misused."  
        },  
        "file": {  
          "type": "string",  
          "description": "File where the finding was detected."  
        },  
        "line": {  
          "type": "integer",  
          "minimum": 1,  
          "description": "Representative line number, usually the sink line."  
        },  
        "source\_kind": {  
          "type": "string",  
          "enum": \[  
            "external\_content",  
            "secret",  
            "llm\_output",  
            "serialized\_artifact",  
            "remote\_model",  
            "tool\_capability"  
          \],  
          "description": "Abstract source family."  
        },  
        "source": {  
          "type": "string",  
          "description": "Concrete source expression or API found in code."  
        },  
        "sink\_kind": {  
          "type": "string",  
          "enum": \[  
            "llm\_input",  
            "system\_prompt",  
            "code\_execution",  
            "shell\_execution",  
            "sql\_execution",  
            "unsafe\_deserialization",  
            "remote\_code\_trust",  
            "destructive\_or\_execution",  
            "external\_side\_effect"  
          \],  
          "description": "Abstract sink family."  
        },  
        "sink": {  
          "type": "string",  
          "description": "Concrete sink expression or API found in code."  
        },  
        "flow": {  
          "type": "string",  
          "description": "Human-readable source-to-sink or capability-to-agent flow summary."  
        },  
        "evidence": {  
          "type": "string",  
          "description": "Representative code snippet or sink line supporting the finding."  
        },  
        "confidence": {  
          "type": "number",  
          "minimum": 0,  
          "maximum": 1,  
          "description": "Confidence in the static detection evidence, not exploitability."  
        }  
      },  
      "additionalProperties": false  
    },  
    "Summary": {  
      "type": "object",  
      "required": \[  
        "total\_findings",  
        "by\_severity",  
        "by\_status",  
        "by\_category"  
      \],  
      "properties": {  
        "total\_findings": {  
          "type": "integer",  
          "minimum": 0  
        },  
        "by\_severity": {  
          "type": "object",  
          "required": \["critical", "high", "medium", "low"\],  
          "properties": {  
            "critical": {  
              "type": "integer",  
              "minimum": 0  
            },  
            "high": {  
              "type": "integer",  
              "minimum": 0  
            },  
            "medium": {  
              "type": "integer",  
              "minimum": 0  
            },  
            "low": {  
              "type": "integer",  
              "minimum": 0  
            }  
          },  
          "additionalProperties": false  
        },  
        "by\_status": {  
          "type": "object",  
          "required": \["vulnerable", "risky"\],  
          "properties": {  
            "vulnerable": {  
              "type": "integer",  
              "minimum": 0  
            },  
            "risky": {  
              "type": "integer",  
              "minimum": 0  
            }  
          },  
          "additionalProperties": false  
        },  
        "by\_category": {  
          "type": "object",  
          "description": "Finding counts by OWASP category.",  
          "additionalProperties": {  
            "type": "integer",  
            "minimum": 0  
          }  
        }  
      },  
      "additionalProperties": false  
    }  
  },  
  "additionalProperties": false  
}  
 