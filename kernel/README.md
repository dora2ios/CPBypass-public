# CP-Bypass - kernel 

syscallによる脱獄検知を回避するKernel Patch  
注意: ほとんどのアプリでは通常のファイル検知も行なっているようなので、こちらはMobileSubstrateによるHookingで対応する必要があります。  

## 動作環境  
- non-KPP/KTRR devices  
- KPP devices (iOS 10.0-10.3.3)  

## 対応状況  
### armv7    
- sysent_patch32.cをビルドして脱獄環境でカーネルパッチすることで動作するようになります。  
- コンソールからkernelプロセスを確認することで_stat()が呼ばれた際のパスの確認が行えます。  
32-bitのiOS 7.1-9.0.2 (8.4.1を除く)で脱獄している場合、脱獄ツールによるsb_evaluate()をHookするpayloadと位置が競合する可能性があります。パッチ前にpayloadの位置を確認した上で、被るようならアドレスをズラしてください。  

  
### arm64(KPP devices)  
sysent_patch64.cは不完全なコードです。このコードはyalu102のKPP bypassを利用する脱獄に組み込むことで利用できます。  
64bit環境では現在IOLogによるログ出力が機能していません。  

