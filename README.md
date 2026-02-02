# MMInjector
Manual Map Injector

サスペンド状態で起動し、dllをメモリに展開します。

管理者権限が必要で、ターゲットが開かれてない状態にする必要があります。

## settings.json
dllName: dllファイルが必ず同じフォルダに入ってることを確認してください

targetFullPath: ターゲットとするexeファイルのフルパです。階層を示すバックスラッシュは２つ必要です

```json
{
    "dllName": "test.dll",
    "targetFullPath": "D:\\game.exe"
}
```

https://discord.gg/7c38bMcMK5
