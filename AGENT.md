# web-to-shell (원격 에이전트)

이 호스트는 HTTP GET으로만 조작한다. 서명되지 않은 요청은 거부된다.

준비물: `BASE_URL`(클플 터널 origin, 끝 슬래시 없음), 호스트 `authorized.asc`에 대응하는 PGP 비밀키. 비밀키를 이 파일·로그·URL에 넣지 말 것.

## 요청

```
GET {BASE_URL}/web-to-shell/{action}/{sig}/{payload}
```

- method: GET만. POST/PUT 불가.
- `action`: `terminal` | `read-file` | `edit-file`
- `payload`: JSON UTF-8 바이트의 **표준 base64**. 경로에 넣을 때 `encodeURIComponent`.
- `sig`: 그 JSON 바이트에 대한 **detached PGP 서명**(armored)의 UTF-8을 **base64url**.
- 서명 대상은 URL이 아니라 **payload를 base64 decode한 원본 JSON 바이트**. 텍스트 모드 서명 금지(개행 정규화됨).
- JSON은 객체 하나. `JSON.stringify`를 **한 번만** 해서 그 문자열을 서명·인코딩에 같이 쓴다. 키 순서가 바뀌면 서명이 깨진다.

## JSON

모든 요청에 `exp`(unix 초, number) 필수. 현재 시각보다 과거면 거부. 보통 `now+3600`.

### terminal

```json
{"command":"ls -la","exp":1730000000}
```

호스트에서 셸로 실행. timeout 30s, stdout/stderr 합쳐 약 2MB.

### read-file

```json
{"path":"/absolute/or/relative","exp":1730000000}
```

UTF-8 텍스트. 10MB 초과·디렉터리·없는 파일은 실패. 상대경로는 서버 cwd 기준.

### edit-file

```json
{"path":"/absolute/or/relative","oldText":"기존 조각","newText":"새 조각","exp":1730000000}
```

`oldText` **첫 번째** 등장만 교체. 없으면 실패. `oldText`는 빈 문자열 불가. `newText`는 빈 문자열 가능(삭제).

## 서명 (Node, openpgp)

```js
import * as openpgp from 'openpgp';

export async function signedUrl(baseUrl, action, body, armoredPrivateKey, passphrase) {
  if (!body.exp) body.exp = Math.floor(Date.now() / 1000) + 3600;
  const json = JSON.stringify(body);
  let key = await openpgp.readPrivateKey({ armoredKey: armoredPrivateKey });
  if (!key.isDecrypted()) {
    key = await openpgp.decryptKey({ privateKey: key, passphrase });
  }
  const detached = await openpgp.sign({
    message: await openpgp.createMessage({ binary: new TextEncoder().encode(json) }),
    signingKeys: key,
    detached: true,
  });
  const sig = Buffer.from(detached, 'utf8').toString('base64url');
  const payload = encodeURIComponent(Buffer.from(json, 'utf8').toString('base64'));
  return `${baseUrl.replace(/\/$/, '')}/web-to-shell/${action}/${sig}/${payload}`;
}
```

그 URL로 `GET`. 본문 없음.

## 응답

`Content-Type: application/json`

| HTTP | 의미 |
|------|------|
| 200 | 성공 |
| 400 | JSON/만료/경로/oldText 등 |
| 401 | 서명 실패 |
| 404 | 경로 아님 |
| 405 | GET 아님 |
| 500 | 명령 비정상 종료 |

terminal 성공/실패:

```json
{"ok":true,"stdout":"...","stderr":"...","code":0}
{"ok":false,"stdout":"...","stderr":"...","code":1,"error":"..."}
```

read-file: `{"ok":true,"content":"..."}`  
edit-file: `{"ok":true}`  
그 외 실패: `{"ok":false,"error":"..."}`

## 사용 규칙

1. 호스트에서 실제로 명령이 실행된다. 추측으로 `rm`/덮어쓰기/권한 변경 하지 말 것.
2. 파일을 고치기 전에 `read-file`로 현재 내용을 본다. `oldText`는 파일에 있는 그대로(공백·개행 포함).
3. 한 번에 한 조각만 바꾼다. 여러 곳이면 `edit-file`을 반복한다.
4. `exp`가 지난 URL은 재서명한다. 같은 URL 재사용은 만료 전에도 가능하므로 파괴적 명령 URL을 공유하지 말 것.
5. 출력은 2MB에서 잘린다. 큰 파일은 `terminal`로 `sed`/`head` 하거나 `read-file`을 쓴다.
