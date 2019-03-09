---
layout: post
title: "Obfuscaxor - TAMUCTF"
date: 2019-03-09 16:21:06
tags: CTFWriteup Reversing TamuCTF Xor
description: CTF TamuCTF, Categoria RE
---

Archivo: [obfuscaxor](/assets/posts/obfuscaxor/obfuscaxor)
Servidor: rev.tamuctf.com:7224

```
$ file obfuscaxor
obfuscaxor: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=87d50894cc43d26512e0b06404813718221dde40,
not stripped
```

<p style='text-align: justify;'>
Al cargar el programa en IDA lo primero que podemos observar es que no solicita una llave de producto la cual pasa como parametro
a la función _Z10verify_keyPc y si dicha funcion regresa un valor diferente de 0 pasara a darnos el flag.
</p>

![Main]({{ '/assets/posts/obfuscaxor/main.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
En la funcion _Z10verify_keyPc encontramos que las primeras validacion es que la longitud de la llave sea mayor a 9 y menor o igual que 0x40 y en caso
de pasar las validaciones pasa nuestro string a la funcion _Z3encPKc, a su vez podemos observar un bloque de código que es el unico que antes de salir 
de la funcion puede estrablecer al a 1 y ademas depende de la comparación de 2 strings por lo que es probable que esta sea la comparación que valide la llave.
</p>

```
	call _strcmp   ;llama la comparacion de 2 strings
	test eax, eax  ;ZF=1 si eax=0, eax=0 si ambos parametros de strcmp son iguales
	setz al        ;al=1 si ZF=1
```

![_Z10verify_keyPc]({{ '/assets/posts/obfuscaxor/verifykeypc.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Un enfoque que me gusta tomar es establecer breakpoints en las zonas que me interesa, antes de seguir todas las funciones, para cuando llegue ahí observar los parametros
y ver si uno de esos parametros es nuestro input. Desde ya podemos ver que uno de los parametros del strcmp lo carga con la instruccion:
</p>

```
lea [rbp+s1],unk_55B32B831C00
```

<p style='text-align: justify;'>
y al ver el contenido de unk_55B32B831C00 podemos ver su contenido
</p>

![Hardcoded Key]({{ '/assets/posts/obfuscaxor/hardcoded_key.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Sin embargo al analizar S2 en tiempo de ejecución podemos observar que S2 solo se parece a nuestro input en longitud mas no en el contenido. Por el nombre del reto 
podemos asumir que es un operacion XOR, sin embargo necesitamos encontrar la llave para lo cual tenemos 2 opciones: analizar _Z3encPKc o hacer XOR de S2 contra
nuestro input e intentar hacer XOR del resultado de la operacion anterior contra S1 y probar el resultado como nuestro input para ver si de casualidad funciona. 

Lo anterior es posible gracias a como opera el XOR, recordemos que:
</p>
```
	S2 = input XOR llave 
	
	despejamos llave
	
	llave = input  XOR S2
```

<p style='text-align: justify;'>
Con lo anterior podriamos intentar una solucion como la siguiente:
</p>

```python
from pwn import *


sinput = '1234567890abcedf' #input patron de longitud igual a la longitud de la llave que encontramos en el codigo
s2 = [0xef,0x9f,0x8d,0xdb,0xeb,0x9b,0x89,0xd7,0xe7,0x9d,0xdf,0x8d,0xbd,0xc8,0xda,0x89] #S2, obtenido en tiempo de ejecución
s1 = [0xAE,0x9E,0xFF,0x9C,0xAB,0xC7,0xD3,0x81,0xE7,0xEE,0xFB,0x8A,0x9D,0x0EF,0x8D,0x0AE] #S1, obtenido del binario
result = ''

for i in range(0,len(sinput)):
	xorkey = ord(sinput[i])^s2[i]
	result += chr(xorkey^s1[i])

conn = remote('rev.tamuctf.com',7224)
print conn.recvline()
print conn.recvline()
conn.send(result+"\n")
print conn.recvline()
```
<p style='text-align: justify;'>
	El ejecutar el codigo anterior vemos que efectivamente nos da el flag el servidor, cabe destacar que durante el CTF no se me ocurrio sacarlo de esta manera
	sino que el enfoque fue mas bien analizar _Z3encPKc e ir analizando las diferentes funciones para ver que hacía lo cual basicamente se reducia a 4 funciones que regresan
	un int para pasarlo a otra funcion donde hace un xor contra una constante (0x676), nuevamente le hace un xor contra otro valor para finalmente tomar solamente un byte,
	en el código se pueen observar 5 funciones, sin embargo el 5° calculo simplemente da 0 como resultado. Posteriormente dichos valores los pasa a otra función junto con
	el input y va codificando cada uno de nuestros caracteres contra el que corresponda de los calculados anteriores en base al indice del caracter % 4.
	
</p>
![Xor Key]({{ '/assets/posts/obfuscaxor/xorkey.png' | relative_url }}){: .center-image }

