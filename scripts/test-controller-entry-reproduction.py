#!/usr/bin/env python3
"""End-to-end controller-owned handler proof in the actual isolated adapters.

Tests only owned local fixtures. No external targets, network or model.
"""
import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from source_reproduction import run_probe

def files(root, documents):
    for path, content in documents.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)

def probe(root, path, function, nonce='1'*32):
    return run_probe(root, dict(file=path, function=function,
                                kind='entry_html_reflection',nonce=nonce))

with tempfile.TemporaryDirectory(prefix='lotus-controller-entry-') as dirname:
    root=Path(dirname).resolve()
    files(root, {
        'src/__init__.py':'',
        'src/renderer.py':'def render(value):\n    return "<p>" + value + "</p>"\n',
        'src/http_handler.py':(
            'from urllib.parse import parse_qs, urlsplit\n'
            'from src.renderer import render\n'
            'def response_body(url):\n'
            '    text=parse_qs(urlsplit(url).query).get("message", [""])[0]\n'
            '    return render(text)\n'
        ),
        'src/handler.cjs':(
            'exports.responseBody=function responseBody(url){\n'
            'const text=new URL(url,"http://localhost").searchParams.get("message")||"";\n'
            'return "<p>"+text+"</p>";};\n'
        ),
        'src/escaped-handler.cjs':(
            'exports.responseBody=function responseBody(url){\n'
            'const text=new URL(url,"http://localhost").searchParams.get("message")||"";\n'
            'return "<p>"+text.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")+"</p>";};\n'
        ),
        'src/main/java/org/lotus/HttpHandler.java':(
            'package org.lotus;\n'
            'public class HttpHandler {\n'
            'public String responseBody(String value) {return "<p>"+value+"</p>";}\n'
            '}\n'
        ),
        'src/main/java/org/lotus/EncodedHandler.java':(
            'package org.lotus;\n'
            'public class EncodedHandler {\n'
            'public String responseBody(String value) {return "<p>"+value.replace("<","&lt;")+"</p>";}\n'
            '}\n'
        ),
    })
    targets=[
        ('src/http_handler.py','response_body'),
        ('src/handler.cjs','responseBody'),
        ('src/main/java/org/lotus/HttpHandler.java','HttpHandler.responseBody')
    ]
    for index,(path,function) in enumerate(targets):
        result=probe(root,path,function,nonce=hex(index+1)[2:].rjust(32,'0'))
        assert result['status']=='behavior_observed',(path,result)
        observed=result['observations']
        assert 'TOMEY_PROBE' in observed['attack_output'],(path,observed)
        assert observed['control_input'] in observed['control_output'],(path,observed)
        if path.endswith('.py') or path.endswith('.cjs'):
            assert 'message=' in observed['entry_attack_url'],(path,observed)
            assert '%3Cem' in observed['entry_attack_url'],(path,observed)
            assert observed['entry_selector']==function,(path,observed)

    for path,function in [
        ('src/escaped-handler.cjs','responseBody'),
        ('src/main/java/org/lotus/EncodedHandler.java','EncodedHandler.responseBody')
    ]:
        result=probe(root,path,function)
        assert result['status']=='behavior_not_observed',(path,result)
        assert result['behavior_observed'] is False,(path,result)

    invalid=probe(root,'src/renderer.py','render')
    assert invalid['status']=='invalid_probe',invalid
    print('Controller entry-to-output Python/JavaScript/Java sandboxes and escaped negative controls PASSED')
