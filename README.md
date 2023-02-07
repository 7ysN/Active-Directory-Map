# Active Directory Map !

**This script contains the Microsoft Active Directory Module DLL which is compressed and encoded to a Base64 string.**
**The script takes the encoded Base64 string, decodes and decompresses it, and then loads it into the system memory.**
**The main purpose of this script is to help map the Domain environment.**

## Usage:
`PS C:\Tmp> . .\ActiveDirectoryMap.ps1`

![1](https://user-images.githubusercontent.com/62604022/193838948-a158a4a7-efa1-4917-94bf-b382bcdd34b2.png)

### Functions:
**The script contains multiple functions:**
1. **UsersList** - `To List All Domain Users`
2. **GroupsList** - `To List All Domain Groups`
3. **UsersMembership** - `To Check The User's Group Membership`
4. **DoesNotRequirePreAuth** - `To List All Users Which Don't Require Pre-Auth`
5. **ServicePrincipalName** - `To List All Users Which have Service Principal Name`
6. **Help** - `To see all available functions in this script`


## Examples
### 1. Help:
![2023-02-07 15_13_53-win10 (win10 clear)  Running  - Oracle VM VirtualBox](https://user-images.githubusercontent.com/62604022/217254691-aef9847b-14da-4f29-afd7-22c930fee433.png)

### 2. UsersList:
![2023-02-07 15_05_46-win10 (win10 clear)  Running  - Oracle VM VirtualBox](https://user-images.githubusercontent.com/62604022/217253937-24fc059b-7d39-454b-b7f6-20d077fd9b3d.png)

### 3. GroupsList:
![2023-02-07 15_06_00-win10 (win10 clear)  Running  - Oracle VM VirtualBox](https://user-images.githubusercontent.com/62604022/217254065-998ee4cd-e72f-4d13-95f1-26231b6b4f77.png)

### 4. UsersMembership:
![2023-02-07 14_37_44-win10 (win10 clear)  Running  - Oracle VM VirtualBox](https://user-images.githubusercontent.com/62604022/217254393-d34ae181-f15c-4b8b-b40c-55ccb5d9e543.png)

### 5. DoesNotRequirePreAuth: 
![2023-02-07 15_11_43-win10 (win10 clear)  Running  - Oracle VM VirtualBox](https://user-images.githubusercontent.com/62604022/217254439-4dbdf759-68c9-4447-a63d-ab3488303779.png)

### 6. ServicePrincipalName:
![2023-02-07 15_06_51-win10 (win10 clear)  Running  - Oracle VM VirtualBox](https://user-images.githubusercontent.com/62604022/217254463-df0f78bd-7c56-4f54-9302-fd2a984ffbec.png)

## Good Luck !
