# Active Directory Map

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
3. **GroupMembership** - `To Check The User's Group Membership`
4. **DoesNotRequirePreAuth** - `To List All Users Which Don't Require Pre-Auth`
5. **ServicePrincipalName** - `To List All Users Which have Service Principal Name`
6. **Help** - `To see all available functions in this script`

----
## Examples:
### 1. Help
![2](https://user-images.githubusercontent.com/62604022/193839009-32134720-8edf-48e8-b240-a205e0975d95.png)

### 2. UsersList

![3](https://user-images.githubusercontent.com/62604022/193839047-eeea615a-8a24-453b-8150-1cf00bcc0b69.png)

### 3. GroupsList

![4](https://user-images.githubusercontent.com/62604022/193839065-c12cc4a6-5a94-43e9-997f-f7ccc28cf036.png)

### 4. GroupMembership
![5](https://user-images.githubusercontent.com/62604022/193839083-b9fe35ca-a6b6-4cb1-bb94-ab2618a0130a.png)

### 5. DoesNotRequirePreAuth & ServicePrincipalName  
![6](https://user-images.githubusercontent.com/62604022/193838494-beb33c5e-ca85-43b1-ad3d-c72c8fc19687.png)
