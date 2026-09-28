# -*- coding: utf-8 -*-
"""Antinel i18n — 集中管理所有用户面字符串。

第一原则：Agent 面的输出保持英文（Agent 天然多语，读完翻译给用户）。
本文件管的是**人类面**的字符串：通知、日报、护盾状态、help。

用法：
    from strings import S
    lang = detect_lang()  # "en"/"zh"/"ja"/...
    print(S[lang]["shield_on"])

新语言 = 加一个 dict 键。未覆盖的字符串自动 fallback 到英文。
"""
import locale
import os

SUPPORTED = ("en", "zh", "ja", "ko", "de", "es", "fr", "pt", "ru", "hi", "id")

# ------------------------------------------------------- 语言检测 ----
_LOCALE_MAP = {
    "zh": "zh", "zh_CN": "zh", "zh_TW": "zh", "zh_HK": "zh",
    "ja": "ja", "ja_JP": "ja",
    "ko": "ko", "ko_KR": "ko",
    "de": "de", "de_DE": "de", "de_AT": "de", "de_CH": "de",
    "es": "es", "es_ES": "es", "es_MX": "es", "es_AR": "es",
    "fr": "fr", "fr_FR": "fr", "fr_CA": "fr",
    "pt": "pt", "pt_BR": "pt", "pt_PT": "pt",
    "ru": "ru", "ru_RU": "ru",
    "hi": "hi", "hi_IN": "hi",
    "id": "id", "id_ID": "id",
    "en": "en", "en_US": "en", "en_GB": "en",
}


def detect_lang():
    """按优先级：1) 环境变量覆盖  2) OS locale  3) 英文兜底"""
    forced = os.environ.get("ANTINEL_LANG")
    if forced and forced in SUPPORTED:
        return forced
    try:
        import locale as _lc
        loc = _lc.getdefaultlocale()[0] or ""
        prefix = loc.split("_")[0].lower()
        if prefix in SUPPORTED:
            return prefix
    except Exception:
        pass
    return "en"


# ------------------------------------------------------- 字符串表 ----
# 每个 key = 一个用户面字符串；每个语言 = 该 key 的翻译（缺省 = 英文）。

_STR = {
    # 通知
    "notify_blocked_title": {
        "en": "Antinel blocked a dangerous operation",
        "zh": "Antinel 已拦下危险操作",
        "ja": "Antinel が危険な操作をブロックしました",
        "ko": "Antinel이 위험한 작업을 차단했습니다",
        "de": "Antinel hat eine gefährliche Operation blockiert",
        "es": "Antinel bloqueó una operación peligrosa",
        "fr": "Antinel a bloqué une opération dangereuse",
        "pt": "Antinel bloqueou uma operação perigosa",
        "ru": "Antinel заблокировал опасную операцию",
        "hi": "Antinel ने एक खतरनाक ऑपरेशन रोक दिया",
        "id": "Antinel memblokir operasi berbahaya",
    },
    "notify_blocked_body": {
        "en": "{what}. Logged. See antinel report --session latest for details.",
        "zh": "{what}。已留痕，详情见 antinel report --session latest。",
        "ja": "{what}。記録済み。詳細は antinel report --session latest。",
        "ko": "{what}. 기록됨. 자세한 내용은 antinel report --session latest.",
        "de": "{what}. Protokolliert. Details: antinel report --session latest.",
        "es": "{what}. Registrado. Detalles: antinel report --session latest.",
        "fr": "{what}. Enregistré. Détails : antinel report --session latest.",
        "pt": "{what}. Registrado. Detalhes: antinel report --session latest.",
        "ru": "{what}. Записано. Подробнее: antinel report --session latest.",
        "hi": "{what}. लॉग किया गया। विवरण: antinel report --session latest।",
        "id": "{what}. Tercatat. Lihat antinel report --session latest.",
    },
    # 护盾
    "shield_on": {
        "en": "Shield: ON (host exfil paths denied by default)",
        "zh": "护盾：开着（宿主外传路径默认拒绝）",
        "ja": "シールド：オン（ホスト外部送信パスはデフォルトで拒否）",
        "ko": "실드: 켜짐 (호스트 유출 경로 기본 거부)",
        "de": "Schild: AN (Host-Exfil-Pfade standardmäßig verweigert)",
        "es": "Escudo: ACTIVADO (rutas de exfiltración denegadas por defecto)",
        "fr": "Bouclier : ACTIVÉ (chemins d'exfiltration refusés par défaut)",
        "pt": "Escudo: LIGADO (caminhos de exfiltração negados por padrão)",
        "ru": "Щит: ВКЛ (пути эксфильтрации по умолчанию отклонены)",
        "hi": "शील्ड: चालू (होस्ट एक्सफिल पथ डिफ़ॉल्ट रूप से अस्वीकृत)",
        "id": "Perisai: AKTIF (jalur exfil host ditolak secara default)",
    },
    "shield_off": {
        "en": "Shield: OFF (default. Enable: antinel host-shield enable)",
        "zh": "护盾：关着（默认。开启：antinel host-shield enable）",
        "ja": "シールド：オフ（デフォルト。有効化：antinel host-shield enable）",
        "ko": "실드: 꺼짐 (기본. 활성화: antinel host-shield enable)",
        "de": "Schild: AUS (Standard. Aktivieren: antinel host-shield enable)",
        "es": "Escudo: APAGADO (predeterminado. Activar: antinel host-shield enable)",
        "fr": "Bouclier : DÉSACTIVÉ (par défaut. Activer : antinel host-shield enable)",
        "pt": "Escudo: DESLIGADO (padrão. Ativar: antinel host-shield enable)",
        "ru": "Щит: ВЫКЛ (по умолчанию. Включить: antinel host-shield enable)",
        "hi": "शील्ड: बंद (डिफ़ॉल्ट। सक्षम करें: antinel host-shield enable)",
        "id": "Perisai: MATI (default. Aktifkan: antinel host-shield enable)",
    },
    # digest 摘要
    "digest_summary": {
        "en": "Last {N} day(s): {P} project(s)/host(s), {A} ops, {B} blocked, "
              "{T} tokens (facts); accounting: {H}={U}.",
        "zh": "近 {N} 天：{P} 个项目/宿主组合，{A} 次操作、拦截 {B} 次、"
              "token 进出 {T}（事实）；记账口径 {H}={U}。",
        "ja": "過去{N}日：{P}プロジェクト/ホスト、{A}操作、ブロック{B}回、"
              "トークン{T}（事実）；会計：{H}={U}。",
        "ko": "최근 {N}일: {P} 프로젝트/호스트, {A} 작업, 차단 {B}회, "
              "토큰 {T} (사실); 회계: {H}={U}.",
        "de": "Letzte {N} Tage: {P} Projekte/Hosts, {A} Ops, {B} blockiert, "
              "{T} Tokens (Fakten); Abrechnung: {H}={U}.",
        "es": "Últimos {N} días: {P} proyectos/hosts, {A} ops, {B} bloqueados, "
              "{T} tokens (hechos); contabilidad: {H}={U}.",
        "fr": "{N} dernier(s) jour(s) : {P} projets/hosts, {A} ops, {B} bloqués, "
              "{T} tokens (faits) ; comptabilité : {H}={U}.",
        "pt": "Últimos {N} dia(s): {P} projetos/hosts, {A} ops, {B} bloqueados, "
              "{T} tokens (fatos); contabilidade: {H}={U}.",
        "ru": "Последние {N} дн.: {P} проектов/хостов, {A} операций, {B} блокировок, "
              "{T} токенов (факты); учёт: {H}={U}.",
        "hi": "पिछले {N} दिन: {P} परियोजनाएं/होस्ट, {A} ऑपरेशन, {B} अवरोधित, "
              "{T} टोकन (तथ्य); लेखा: {H}={U}.",
        "id": "{N} hari terakhir: {P} proyek/host, {A} ops, {B} diblokir, "
              "{T} token (fakta); akuntansi: {H}={U}.",
    },
    # help 首行
    "help_header": {
        "en": "Antinel Security Suite v{V} ｜ Host: {H} (accounting: {U})",
        "zh": "Antinel Security Suite v{V} ｜ 宿主: {H}（记账口径: {U}）",
        "ja": "Antinel Security Suite v{V} ｜ ホスト: {H}（会計: {U}）",
        "ko": "Antinel Security Suite v{V} ｜ 호스트: {H} (회계: {U})",
        "de": "Antinel Security Suite v{V} ｜ Host: {H} (Abrechnung: {U})",
        "es": "Antinel Security Suite v{V} ｜ Host: {H} (contabilidad: {U})",
        "fr": "Antinel Security Suite v{V} ｜ Hôte : {H} (comptabilité : {U})",
        "pt": "Antinel Security Suite v{V} ｜ Host: {H} (contabilidade: {U})",
        "ru": "Antinel Security Suite v{V} ｜ Хост: {H} (учёт: {U})",
        "hi": "Antinel Security Suite v{V} ｜ होस्ट: {H} (लेखा: {U})",
        "id": "Antinel Security Suite v{V} ｜ Host: {H} (akuntansi: {U})",
    },
    "help_say": {
        "en": "── What you can say to the Agent ──",
        "zh": "── 你可以对 Agent 说 ───────────────────────",
        "ja": "── Agent に話しかける ──",
        "ko": "── Agent에게 말할 수 있습니다 ──",
        "de": "── Was Sie dem Agent sagen können ──",
        "es": "── Lo que puede decirle al Agent ──",
        "fr": "── Ce que vous pouvez dire à l'Agent ──",
        "pt": "── O que você pode dizer ao Agent ──",
        "ru": "── Что вы можете сказать Агенту ──",
        "hi": "── आप Agent से क्या कह सकते हैं ──",
        "id": "── Apa yang bisa Anda katakan ke Agent ──",
    },
    "help_cmds": {
        "en": "── Commands (Agent runs them, or you can) ──",
        "zh": "── 命令（Agent 替你跑，也可以自己跑）─────────",
        "ja": "── コマンド（Agent が実行、自分でも可）──",
        "ko": "── 명령어 (Agent가 실행, 직접 실행도 가능) ──",
        "de": "── Befehle (Agent führt sie aus, oder Sie) ──",
        "es": "── Comandos (el Agent los ejecuta, o usted) ──",
        "fr": "── Commandes (l'Agent les exécute, ou vous) ──",
        "pt": "── Comandos (o Agent executa, ou você) ──",
        "ru": "── Команды (Агент выполнит, или вы сами) ──",
        "hi": "── कमांड (Agent चलाएगा, या आप खुद) ──",
        "id": "── Perintah (Agent menjalankan, atau Anda) ──",
    },
    "help_tips": {
        "en": "── Tips ──\n"
              "  Commands in block messages are safe to run; all config changes are audited.\n"
              "  Multi-host machines: Agent self-reports host (antinel --host zcode …).\n"
              "  Principle: record Agent behavior and consumption; never rank humans.",
        "zh": "── 提示 ───────────────────────────────────\n"
              "  拦截消息里给出的命令可直接执行；所有配置变更均进审计链。\n"
              "  多宿主共存机器：Agent 自报宿主（antinel --host zcode …），口径即随宿主。\n"
              "  分寸：记录 Agent 的行为与消耗；不做人的效率排名。",
        # 其他语言 fallback 到英文
    },
    # 铁律（用户须知摘要）
    "iron_never_user_cmd": {
        "en": "Users never run commands — commands are executed and interpreted by the Agent",
        "zh": "用户永远不运行命令——命令由 Agent 执行与解读",
    },
    "iron_data_from_ledger": {
        "en": "Data must come from the ledger",
        "zh": "数据必须来自账本",
    },
    "iron_semantic_match": {
        "en": "Semantic matching, not keyword matching",
        "zh": "语义匹配，不是词表匹配",
    },
    # digest 覆盖声明
    "coverage": {
        "en": "[Coverage] {N} registered project(s) / {M} host(s); unregistered tools not shown",
        "zh": "【覆盖】{N} 个登记项目 / {M} 个宿主；未接入工具不在此列",
        "ja": "【カバー】{N} 登録プロジェクト / {M} ホスト；未登録ツールは表示されません",
        "ko": "[커버리지] {N} 등록 프로젝트 / {M} 호스트; 미등록 도구는 표시되지 않음",
    },
}


def get_string(lang, key, **kwargs):
    """Get a localized string. Fallback: lang → en. Format with kwargs."""
    entry = _STR.get(key)
    if entry is None:
        return key
    text = entry.get(lang) or entry.get("en") or key
    if kwargs:
        try:
            text = text.format(**kwargs)
        except Exception:
            pass
    return text


def get_translation_table(lang):
    """Return the string table for a given language (en fallback per key)."""
    en = _STR.get("en", {})
    loc = _STR.get(lang, {})
    return {k: loc.get(k) or en.get(k, k) for k in en}
