﻿# securityProject
 
## 입력사항
### 아이디
  - admin, manager, user
### 권한
  - ROLE_ADMIN > ROLE_MANAGER > ROLE_USER
### 리소스
|리소스명 | 권한 방식 | 순위 |
|:----------|:----------:|:----------:|
|/admin/**|url|0|
|/mypage|url|1|
|/messaages|url|2|
|io.security.corespringsecurity.aopsecurity.AopMethodService.methodSecured|method|3|
|execution(* io.security.corespringsecurity.aopsecurity.AopPointcutService.pointcut*(..))|pointcut|4|
