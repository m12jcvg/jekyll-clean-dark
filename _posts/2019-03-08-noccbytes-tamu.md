---
layout: post
title: "Noccbytes - TAMUCTF"
date: 2019-03-08 13:25:06
tags: CTFWriteup Reversing TamuCTF
description: CTF TamuCTF, Categoria RE
---

Archivo: [noccbytes](/assets/posts/noccbytes/noccbytes)
Servidor: rev.tamuctf.com:8188

```
$ file noccbytes
noccbytes: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, 
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, 
BuildID[sha1]=dc20579bdbe52f647aa28702ca8d112501b26e36, not stripped
```

<p style='text-align: justify;'>
Al ejecutar el programa podemos observar en la función principal que al ejecutar nos pide un password el cual pasa 
a la función _Z9passCheckPc y si regresa en al un valor diferente de 0 procedera a leer el archivo del flag.
</p>

![Flag]({{ '/assets/posts/noccbytes/flag.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Al analizar la función en cuestion observamos que compara el password que proporcionamos y si es igual asigna ax=1
</p>

![Fake password]({{ '/assets/posts/noccbytes/fake.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Sin embargo al pasarle el password observado nos vuelve a dar Wrong password. Por lo que al hacer un análisis mas profundo observamos que hace 
un barrido a la funcion _Z9passCheckPc con la funcion _Z5checkPh para validar su contenido por lo que se opto por poner un breakpoint al inicio del programa
y ejecutar hasta despues de la funcion y analizar nuevamente _Z9passCheckPc
</p>

![Password correcto]({{ '/assets/posts/noccbytes/good.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Como podemos observar al parecer el programa contiene una rutina para alterar el password en tiempo de ejecución por lo que al proporcionar el password correcto nos da el flag.
</p>

Solucion:

```python
from pwn import *

conn = remote('rev.tamuctf.com',8188)
print conn.recvline()
print conn.recvline()
conn.send("WattoSays\n")
print conn.recvline()
```
