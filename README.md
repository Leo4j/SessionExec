# SessionExec

SessionExec allows you to execute specified commands in other Sessions on Windows Systems, either targeting a specific session ID or All sessions, with the option to suppress command output.

The tool is inspired to the [EOP COM Session Moniker](https://bugs.chromium.org/p/project-zero/issues/detail?id=1021) exploit code, released a long time ago by James Forshaw.

SessionExec utilises Windows APIs to query session information and create processes within those sessions.

Compile SessionExec.cs running the following command from Build Tools for Visual Studio

```
csc /reference:System.Runtime.InteropServices.dll /reference:System.Runtime.InteropServices.RuntimeInformation.dll SessionExec.cs /out:SessionExec.exe
```

Or you can use `Invoke-SessionExec.ps1` which is the same script, but runs in memory using Reflective Load method.

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/SessionExec/main/Invoke-SessionExec.ps1')
```

You can also find a pure powershell implementation of this tool coded by The-Viper-One [here](https://github.com/The-Viper-One/Invoke-SessionExec)

⚠️ NOTE: SYSTEM privileges are required to run this tool successfully. To elevate from Administrator to SYSTEM, use [Invoke-RunAsSystem](https://github.com/Leo4j/Invoke-RunAsSystem)

## Usage

```
SessionExec.exe <SessionID|All> <Command> [/NoOutput]
```
```
Invoke-SessionExec <SessionID|All> <Command> [/NoOutput]
```

Check what sessions are available using the `quser` command. Then run a command on a specific session, or `All` Sessions.

![image](https://github.com/user-attachments/assets/d9026750-2441-4462-a2d3-2d7179964045)

## Thoughts

If you find yourself being a local admin on one or multiple machines within a network, and there are user sessions on those targets, you could use [SessionExec](https://github.com/Leo4j/SessionExec) and [Find-LocalAdminAccess](https://github.com/Leo4j/Find-LocalAdminAccess) together to check if any of those users have local admin access over other machines in the network.

If they do, you could then repeat the process for users having a session on those machines. This chain of actions could theoretically lead to a full domain compromise.

Additionally, you could obtain shells back using [Amnesiac](https://github.com/Leo4j/Amnesiac), capture NTLMv2 hashes and relay them, grab TGTs, and much much more, all in an automated fashion.

I'll implement this concept into [Amnesiac](https://github.com/Leo4j/Amnesiac), and together with [The-Viper-One](https://github.com/The-Viper-One) we are working on implementing it into [PsMapExec](https://github.com/The-Viper-One/PsMapExec) too.

For now, here is a Proof of Concept (PoC):

![SessionExec](https://github.com/user-attachments/assets/b4e29e6f-b4e5-48c9-bd0c-fe44def7d74c)
