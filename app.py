# INFO API SRC BY: @sxbro
#CHANNEL: @snnetwork7
#LIKE GRUOP: @snxff_ind
import asyncio
import time
import httpx
import json
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2, GetWishListItems_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64
from datetime import datetime, timezone, timedelta

# === Settings ===

# API_KEY removed - no key required now

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB54"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = {"IND", "BR", "US", "SAC", "NA", "SG", "RU", "ID", "TW", "VN", "TH", "ME", "PK", "CIS", "BD", "EUROPE"}

# === Flask App Setup ===

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# === Helper Functions ===

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# === Region Credentials (Updated with given IND, BD, BR) ===

def get_account_credentials(region: str) -> str:
    r = region.upper()
    # IND credentials
    if r == "IND":
        return "uid=7402762943&password=4C009D2C2D327B77F964625A38E01A7B072995872BB0D63910BF993AC581CC24"
    # BD credentials
    elif r == "BD":
        return "uid=7404023631&password=13ECA0AE8C220802799E8DEA95319FD894B156ED289A820F1A884DC2863C6442"
    # BR credentials
    elif r == "BR":
        return "uid=7404047134&password=9B60189C8A5E96AA423BA3F8876235BA9502D877A510D58BB952D28D9057B5B4"
    # Other regions - you can add more elif blocks for ME, US, etc.
    elif r == "ME":
        return "uid={add_uid}&password={add_password}"
    elif r in {"US", "SAC", "NA"}:
        return "uid={add_uid}&password={{add_password}}"
    else:
        # Default for all remaining regions (ID, PK, VN, TH, SG, RU, TW, CIS, EUROPE)
        return "uid={add_uid}&password={{add_password}}"

# === Token Generation ===

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip", 'Content-Type': "application/x-www-form-urlencoded"}
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")

async def create_jwt(region: str):
    try:
        account = get_account_credentials(region)
        token_val, open_id = await get_access_token(account)
        body = json.dumps({"open_id": open_id, "open_id_type": "4", "login_token": token_val, "orign_platform_type": "4"})
        proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
        payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)
        url = "https://loginbp.ggpolarbear.com/MajorLogin"
        headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                   'Content-Type': "application/octet-stream", 'Expect': "100-continue", 'X-Unity-Version': "2018.4.11f1",
                   'X-GA': "v1 1", 'ReleaseVersion': RELEASEVERSION}
        async with httpx.AsyncClient() as client:
            resp = await client.post(url, data=payload, headers=headers)
            msg = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, FreeFire_pb2.LoginRes)))
            cached_tokens[region] = {
                'token': f"Bearer {msg.get('token','0')}",
                'region': msg.get('lockRegion','0'),
                'server_url': msg.get('serverUrl','0'),
                'expires_at': time.time() + 25200
            }
    except Exception as e:
        print(f"Failed token creation for {region}: {e}")

async def initialize_tokens():
    tasks = [create_jwt(r) for r in SUPPORTED_REGIONS]
    await asyncio.gather(*tasks)

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)
    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']
    await create_jwt(region)
    info = cached_tokens.get(region, {})
    return info.get('token', ''), info.get('region', ''), info.get('server_url', '')

# === Core Account Fetcher with AUTO-IND REROUTING ===

async def GetAccountInformation(uid, unk, region, endpoint, allow_reroute=True):
    payload = await json_to_proto(json.dumps({'a': uid, 'b': unk}), main_pb2.GetPlayerPersonalShow())
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)
    
    if not server:
        raise Exception(f"Server URL not available for region {region}")
        
    headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
               'Content-Type': "application/octet-stream", 'Expect': "100-continue",
               'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
               'ReleaseVersion': RELEASEVERSION}
               
    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)
        res_data = json.loads(json_format.MessageToJson(decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)))
        
        detected_region = res_data.get('basicInfo', {}).get('region', '').upper()
        
        if (detected_region == "IND" or lock == "IND") and region != "IND" and allow_reroute:
            uid_region_cache[uid] = "IND"
            return await GetAccountInformation(uid, unk, "IND", endpoint, allow_reroute=False)
            
        return res_data

# === Wishlist Function ===

async def GetWishList(uid, region):
    try:
        req = GetWishListItems_pb2.CSGetWishListItemsReq()
        req.account_id = int(uid)
        
        req_json = json_format.MessageToJson(req)
        payload = await json_to_proto(req_json, GetWishListItems_pb2.CSGetWishListItemsReq())
        data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
        
        token, lock, server = await get_token_info(region)
        headers = {'User-Agent': USERAGENT, 'Connection': "Keep-Alive", 'Accept-Encoding': "gzip",
                   'Content-Type': "application/octet-stream", 'Expect': "100-continue",
                   'Authorization': token, 'X-Unity-Version': "2018.4.11f1", 'X-GA': "v1 1",
                   'ReleaseVersion': RELEASEVERSION}
        
        async with httpx.AsyncClient() as client:
            resp = await client.post(server + "/GetWishListItems", data=data_enc, headers=headers, timeout=10.0)
            res = GetWishListItems_pb2.CSGetWishListItemsRes()
            res.ParseFromString(resp.content)
            return json.loads(json_format.MessageToJson(res))
    except Exception as e:
        raise Exception(f"Wishlist API error: {str(e)}")

# === Rank & Helper Functions ===

def get_br_rank_name(rp):
    try:
        rp = int(rp)
    except:
        return "N/A"
    if rp <= 999:
        if rp <= 0: return "Bronze I"
        if rp < 100: return "Bronze II"
        if rp < 200: return "Bronze III"
        if rp < 300: return "Silver I"
        if rp < 400: return "Silver II"
        if rp < 500: return "Silver III"
        if rp < 600: return "Gold I"
        if rp < 700: return "Gold II"
        if rp < 800: return "Gold III"
        if rp < 900: return "Gold IV"
        return "Platinum I"
    if rp < 1300: return "Silver I"
    if rp < 1400: return "Silver II"
    if rp < 1500: return "Silver III"
    if rp < 1600: return "Gold I"
    if rp < 1725: return "Gold I"
    if rp < 1850: return "Gold II"
    if rp < 1975: return "Gold III"
    if rp < 2100: return "Gold IV"
    if rp < 2225: return "Platinum I"
    if rp < 2350: return "Platinum II"
    if rp < 2475: return "Platinum III"
    if rp < 2600: return "Platinum IV"
    if rp < 2750: return "Platinum V"
    if rp < 2900: return "Diamond I"
    if rp < 3050: return "Diamond II"
    if rp < 3200: return "Diamond III"
    if rp < 3350: return "Diamond IV"
    if rp < 3500: return "Diamond V"
    if rp < 3800: return "Heroic"
    if rp < 4300: return "Heroic"
    if rp < 4900: return "Elite Heroic"
    if rp < 5500: return "Elite Heroic"
    if rp < 6300: return "Elite Heroic"
    if rp < 7100: return "Master"
    if rp < 8000: return "Master"
    if rp < 9000: return "Elite Master"
    return "Elite Master"

def get_br_rank_with_score(rp):
    try:
        rp = int(rp)
        return f"{get_br_rank_name(rp)} ({rp})"
    except:
        return "N/A"

def get_cs_rank_name(rp):
    try:
        rp = int(rp)
    except:
        return "N/A"
    if rp <= 0: return "Bronze I"
    if rp < 100: return "Bronze I"
    if rp < 200: return "Bronze II"
    if rp < 300: return "Bronze III"
    if rp < 400: return "Silver I"
    if rp < 500: return "Silver II"
    if rp < 600: return "Silver III"
    if rp < 700: return "Gold I"
    if rp < 800: return "Gold II"
    if rp < 900: return "Gold III"
    if rp < 1000: return "Gold IV"
    if rp < 1100: return "Platinum I"
    if rp < 1200: return "Platinum II"
    if rp < 1300: return "Platinum III"
    if rp < 1400: return "Platinum IV"
    if rp < 1500: return "Platinum V"
    if rp < 1600: return "Diamond I"
    if rp < 1700: return "Diamond II"
    if rp < 1800: return "Diamond III"
    if rp < 1900: return "Diamond IV"
    if rp < 2000: return "Diamond V"
    if rp < 2500: return "Heroic"
    if rp < 3000: return "Elite Heroic"
    if rp < 3500: return "Master"
    return "Elite Master"

def get_cs_rank_with_score(rp):
    try:
        rp = int(rp)
        return f"{get_cs_rank_name(rp)} ({rp})"
    except:
        return "N/A"

def add_rank_info(data):
    try:
        basic = data.get('basicInfo', {})
        if basic:
            br_rp = basic.get('rankingPoints', 0)
            cs_rp = basic.get('csRankingPoints', 0)
            basic['rank_name'] = get_br_rank_with_score(br_rp)
            basic['cs_rank_name'] = get_cs_rank_with_score(cs_rp)
        
        captain = data.get('captainBasicInfo', {})
        if captain:
            br_rp = captain.get('rankingPoints', 0)
            cs_rp = captain.get('csRankingPoints', 0)
            captain['rank_name'] = get_br_rank_with_score(br_rp)
            captain['cs_rank_name'] = get_cs_rank_with_score(cs_rp)
    except:
        pass
    return data

def format_timestamp_bst(timestamp):
    try:
        dt = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
        bst = timezone(timedelta(hours=6))
        dt_bst = dt.astimezone(bst)
        return dt_bst.strftime("%d %B %Y at %I:%M:%S %p") + " (BST)"
    except:
        return "Unknown"

# === Region Finder with IND Auto Switch ===

def find_best_region(uid):
    if uid in uid_region_cache:
        return uid_region_cache[uid]
    
    # Priority Check: IND, BD, then Others
    check_order = ["IND", "BD"] + [r for r in SUPPORTED_REGIONS if r not in {"IND", "BD"}]
    
    for region in check_order:
        try:
            data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow", allow_reroute=False))
            basic = data.get('basicInfo', {})
            if basic.get('accountId'):
                real_region = basic.get('region', region).upper()
                uid_region_cache[uid] = real_region
                return real_region
        except:
            continue
    
    return None

def resolve_region(uid, force_region=None):
    if force_region and force_region.upper() in SUPPORTED_REGIONS:
        region = force_region.upper()
        uid_region_cache[uid] = region
        return region
    return find_best_region(uid)

def add_equipped_items(data):
    try:
        basic = data.get('basicInfo', {})
        if basic:
            equipped = {
                "weapon_skins": basic.get('weaponSkinShows', []),
                "pin_id": basic.get('pinId', 0),
                "banner_id": basic.get('bannerId', 0),
                "head_pic": basic.get('headPic', 0),
                "title": basic.get('title', 0),
                "badge_id": basic.get('badgeId', 0),
                "equipped_animation_id": basic.get('equippedAnimationId', 0)
            }
            basic['equipped_items'] = equipped
        #made_by: @minister_69
        profile = data.get('profileInfo', {})
        if profile:
            equipped_profile = {
                "avatar_id": profile.get('avatarId', 0),
                "skin_color": profile.get('skinColor', 0),
                "clothes": profile.get('clothes', []),
                "equipped_skills": profile.get('equipedSkills', []),
                "is_selected": profile.get('isSelected', False),
                "is_selected_awaken": profile.get('isSelectedAwaken', False),
                "equipped_animation_id": profile.get('equippedAnimationId', 0)
            }
            profile['equipped_items'] = equipped_profile
        
        captain = data.get('captainBasicInfo', {})
        if captain:
            equipped_captain = {
                "weapon_skins": captain.get('weaponSkinShows', []),
                "pin_id": captain.get('pinId', 0),
                "banner_id": captain.get('bannerId', 0),
                "head_pic": captain.get('headPic', 0),
                "title": captain.get('title', 0),
                "badge_id": captain.get('badgeId', 0),
                "equipped_animation_id": captain.get('equippedAnimationId', 0)
            }
            captain['equipped_items'] = equipped_captain
    except Exception:
        pass
    return data

# ======================================================
# ALL API KEY CHECKS REMOVED – NO AUTHENTICATION REQUIRED
# ======================================================

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]
            res = fn(*a, **k)
            cache[key] = res
            return res
        return wrapper
    return decorator

# === 1. Info Endpoint ===

@app.route('/info')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    region = resolve_region(uid, request.args.get('region'))
    if not region:
        return jsonify({"error": "UID not found in any region."}), 404
        
    try:
        return_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        return_data = add_rank_info(return_data)
        return_data = add_equipped_items(return_data)
        
        if 'diamondCostRes' in return_data:
            del return_data['diamondCostRes']
        
        basic = return_data.get('basicInfo', {})
        if basic:
            if basic.get('createAt'):
                basic['createAt_bst'] = format_timestamp_bst(basic.get('createAt', '0'))
            if basic.get('lastLoginAt'):
                basic['lastLoginAt_bst'] = format_timestamp_bst(basic.get('lastLoginAt', '0'))
        
        formatted_json = json.dumps(return_data, indent=2, ensure_ascii=False)
        return formatted_json, 200, {'Content-Type': 'application/json; charset=utf-8'}
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch data for region {region}: {str(e)}"}), 500

# === 2. Level Endpoint ===

@app.route('/level')
@cached_endpoint(ttl=300)
def get_level_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    region = resolve_region(uid, request.args.get('region'))
    if not region:
        return jsonify({"error": "UID not found in any region."}), 404
    
    try:
        data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        basic = data.get('basicInfo', {})
        
        level = basic.get('level', 0)
        exp = basic.get('exp', 0)
        
        TOTAL_EXP_TO_LEVEL_100 = 32032278
        remaining_exp = max(0, TOTAL_EXP_TO_LEVEL_100 - exp)
        
        exp_to_next = 0
        exp_needed_for_next_level = 0
        if level < 100:
            level_exp = [
                100, 300, 600, 1000, 1500, 2100, 2800, 3600, 4500, 5500,
                6600, 7800, 9100, 10500, 12000, 13600, 15300, 17100, 19000, 21000,
                23100, 25300, 27600, 30000, 32500, 35100, 37800, 40600, 43500, 46500,
                49600, 52800, 56100, 59500, 63000, 66600, 70300, 74100, 78000, 82000,
                86100, 90300, 94600, 99000, 103500, 108100, 112800, 117600, 122500, 127500,
                132600, 137800, 143100, 148500, 154000, 159600, 165300, 171100, 177000, 183000,
                189100, 195300, 201600, 208000, 214500, 221100, 227800, 234600, 241500, 248500,
                255600, 262800, 270100, 277500, 285000, 292600, 300300, 308100, 316000, 324000,
                332100, 340300, 348600, 357000, 365500, 374100, 382800, 391600, 400500, 409500,
                418600, 427800, 437100, 446500, 456000, 465600, 475300, 485100, 495000, 505000
            ]
            if level >= 1 and level <= len(level_exp):
                exp_needed_for_next_level = level_exp[level - 1]
                exp_to_next = max(0, exp_needed_for_next_level - exp)
        
        level_info = {
            "uid": uid,
            "username": basic.get('nickname', 'Unknown'),
            "region": basic.get('region', region),
            "level": level,
            "exp": exp,
            "likes": basic.get('liked', 0),
            "badge_count": basic.get('badgeCnt', 0),
            "exp_to_next_level": exp_to_next,
            "exp_needed_for_next_level": exp_needed_for_next_level,
            "total_exp_needed_for_level_100": remaining_exp
        }
        
        return jsonify(level_info), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch level info: {str(e)}"}), 500

# === 3. Region Endpoint ===

@app.route('/region')
@cached_endpoint(ttl=300)
def get_region_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    region = resolve_region(uid, request.args.get('region'))
    if not region:
        return jsonify({"error": "UID not found in any region."}), 404
    
    try:
        data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        basic = data.get('basicInfo', {})
        
        region_info = {
            "uid": uid,
            "username": basic.get('nickname', 'Unknown'),
            "region": basic.get('region', region),
            "level": basic.get('level', 0),
            "likes": basic.get('liked', 0),
            "created_at": format_timestamp_bst(basic.get('createAt', '0')),
            "last_login": format_timestamp_bst(basic.get('lastLoginAt', '0')),
            "has_elite_pass": basic.get('hasElitePass', False),
            "account_type": basic.get('accountType', 0),
            "season_id": basic.get('seasonId', 0),
            "release_version": basic.get('releaseVersion', 'Unknown')
        }
        
        return jsonify(region_info), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch region info: {str(e)}"}), 500

# === 4. Wishlist Endpoint ===

@app.route('/wishlist')
@cached_endpoint(ttl=300)
def get_wishlist():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    region = resolve_region(uid, request.args.get('region'))
    if not region:
        return jsonify({"error": "UID not found in any region."}), 404
    
    try:
        data = asyncio.run(GetWishList(uid, region))
        items = data.get('items', [])
        
        try:
            info_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            username = info_data.get('basicInfo', {}).get('nickname', 'Unknown')
            level = info_data.get('basicInfo', {}).get('level', 0)
            last_login = info_data.get('basicInfo', {}).get('lastLoginAt', 0)
            real_region = info_data.get('basicInfo', {}).get('region', region)
        except:
            username = 'Unknown'
            level = 0
            last_login = 0
            real_region = region
        
        formatted_items = []
        for item in items:
            formatted_items.append({
                "item_id": item.get('itemId', item.get('item_id', 0)),
                "release_time": item.get('releaseTime', item.get('release_time', 0))
            })
        
        return jsonify({
            "uid": uid,
            "username": username,
            "region": real_region,
            "level": level,
            "last_login": format_timestamp_bst(last_login),
            "total_items": len(formatted_items),
            "items": formatted_items,
            "source": "wishlist_api"
        }), 200
        
    except Exception as e:
        try:
            data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
            basic = data.get('basicInfo', {})
            weapon_skins = basic.get('weaponSkinShows', [])
            
            return jsonify({
                "uid": uid,
                "username": basic.get('nickname', 'Unknown'),
                "region": basic.get('region', region),
                "level": basic.get('level', 0),
                "last_login": format_timestamp_bst(basic.get('lastLoginAt', 0)),
                "displayed_weapons": weapon_skins,
                "total_weapons": len(weapon_skins),
                "source": "fallback_skins",
                "note": "Wishlist API failed. Showing displayed weapon skins instead.",
                "error": str(e)
            }), 200
            
        except Exception as e2:
            return jsonify({
                "error": "Failed to fetch any data.",
                "wishlist_error": str(e),
                "skin_error": str(e2)
            }), 500

# === 5. Leader Endpoint ===

@app.route('/leader')
@cached_endpoint(ttl=300)
def get_leader_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID."}), 400
    
    region = resolve_region(uid, request.args.get('region'))
    if not region:
        return jsonify({"error": "UID not found in any region."}), 404
    
    try:
        user_data = asyncio.run(GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow"))
        
        captain_basic = user_data.get('captainBasicInfo', {})
        clan_basic = user_data.get('clanBasicInfo', {})
        
        if not captain_basic or not clan_basic:
            return jsonify({"error": "User is not in a clan or no leader found."}), 404
        
        captain_uid = captain_basic.get('accountId')
        
        leader_data = asyncio.run(GetAccountInformation(captain_uid, "7", region, "/GetPlayerPersonalShow"))
        leader_basic = leader_data.get('basicInfo', {})
        leader_profile = leader_data.get('profileInfo', {})
        
        br_rp = leader_basic.get('rankingPoints', 0)
        cs_rp = leader_basic.get('csRankingPoints', 0)
        br_rank_name = get_br_rank_with_score(br_rp)
        cs_rank_name = get_cs_rank_with_score(cs_rp)
        
        leader_info = {
            "uid": captain_uid,
            "username": leader_basic.get('nickname', 'Unknown'),
            "region": leader_basic.get('region', region),
            "level": leader_basic.get('level', 0),
            "exp": leader_basic.get('exp', 0),
            "likes": leader_basic.get('liked', 0),
            "rank": leader_basic.get('rank', 0),
            "ranking_points": leader_basic.get('rankingPoints', 0),
            "rank_name": br_rank_name,
            "cs_rank_name": cs_rank_name,
            "max_rank": leader_basic.get('maxRank', 0),
            "cs_rank": leader_basic.get('csRank', 0),
            "cs_ranking_points": leader_basic.get('csRankingPoints', 0),
            "badge_count": leader_basic.get('badgeCnt', 0), #made_by: @minister_69
            "badge_id": leader_basic.get('badgeId', 0),
            "title": leader_basic.get('title', 0),
            "banner_id": leader_basic.get('bannerId', 0),
            "head_pic": leader_basic.get('headPic', 0),
            "pin_id": leader_basic.get('pinId', 0),
            "has_elite_pass": leader_basic.get('hasElitePass', False),
            "account_type": leader_basic.get('accountType', 0),
            "season_id": leader_basic.get('seasonId', 0),
            "release_version": leader_basic.get('releaseVersion', 'Unknown'),
            "created_at": format_timestamp_bst(leader_basic.get('createAt', '0')),
            "last_login": format_timestamp_bst(leader_basic.get('lastLoginAt', 0)),
            "weapon_skins": leader_basic.get('weaponSkinShows', []),
            "equipped_items": {
                "avatar_id": leader_profile.get('avatarId', 0),
                "skin_color": leader_profile.get('skinColor', 0),
                "clothes": leader_profile.get('clothes', []),
                "equipped_skills": leader_profile.get('equipedSkills', []),
                "is_selected": leader_profile.get('isSelected', False),
                "is_selected_awaken": leader_profile.get('isSelectedAwaken', False),
                "pve_primary_weapon": leader_profile.get('pvePrimaryWeapon', 0),
                "equipped_animation_id": leader_profile.get('equippedAnimationId', 0)
            },
            "clan_name": clan_basic.get('clanName', 'Unknown'),
            "clan_id": clan_basic.get('clanId', 'Unknown'),
            "clan_level": clan_basic.get('clanLevel', 0),
            "clan_capacity": clan_basic.get('capacity', 0),
            "clan_members": clan_basic.get('memberNum', 0),
            "is_leader": True
        }
        
        return jsonify(leader_info), 200
        
    except Exception as e:
        return jsonify({"error": f"Failed to fetch leader info: {str(e)}"}), 500

# === Refresh Tokens Endpoint (No API Key needed) ===

@app.route('/refresh', methods=['GET','POST'])
def refresh_tokens_endpoint():
    try:
        asyncio.run(initialize_tokens())
        return jsonify({'message':'Tokens refreshed for all regions.'}),200
    except Exception as e:
        return jsonify({'error': f'Refresh failed: {e}'}),500

# === Clear Cache Endpoint (No API Key needed) ===

@app.route('/clear_cache', methods=['GET','POST'])
def clear_cache():
    uid = request.args.get('uid')
    if uid:
        if uid in uid_region_cache:
            del uid_region_cache[uid]
        return jsonify({"message": f"Cache cleared for UID: {uid}"}), 200
    else:
        uid_region_cache.clear()
        cache.clear()
        return jsonify({"message": "All cache cleared"}), 200

# === Startup ===

async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5000, debug=True)