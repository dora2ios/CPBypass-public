# CP-Bypass Public  

****による脱獄検知を回避するTweak/Patch  

## 動作環境  
- non-KPP/KTRR devices  
- KPP devices (iOS 10.0-10.3.3)  

## 使い方
### kernel patch  
32-bitの場合: インストール後、Terminalから`sysent_patch -p`を実行してカーネルにパッチを適用。  
64-bit (KPP devices)の場合: KPP bypassを行ってCPBypassのカーネルパッチを追加した脱獄を適用。  

### mobile substrate  
共通: `/Library/MobileSubstrate/DynamicLibraries/cpbypass.plist`に回避を実行したいアプリのバンドルIDを追加して起動。  

## 対応状況  
### デバイス  
32-bitプロセッサ搭載のiOS 10デバイスであればパッチを実行することで動きます。  
64-bitプロセッサ搭載デバイスの場合、iOS 8.4.1以下、またはiOS 10.0-10.3.3のKPPデバイスで動作確認済です。ただし、iOS 10.0-10.3.3ではカーネルパッチを行う際にKPP(/KTRR) Bypassが必要となります。  

### アプリ対応状況一覧  


### 対応アプリの追加  
アプリによって確認しているパスに差異があるため、一部回避できないものがあります。ほとんどの場合はsyscallでの検知以外が入っているため、こちらの回避も必要となります。  
32-bitデバイスを使用できるアプリであれば、カーネルにパッチすることでIOLogから検知パスの情報を得ることができます。  
****の検知手法が現状のまま変わらなければsyscallによる検知の回避は簡単に対応可能です。  
64-bitデバイスでは現バージョンではログの出力がうまくいっていないようです。  

## Credits  
[cp-c](https://github.com/akusio/cp-c) by akusio  

2020/12/12  made by dora2ios  
2020/12/16 update: for 64bit  
2021/02/28 public release (under GPLv3)  
