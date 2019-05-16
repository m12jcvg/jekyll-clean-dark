---
layout: post
title: "Babytrace - Defcon Quals 19"
date: 2019-04-02 22:27:00
tags: CTFWriteup Reversing DefconQuals Angr
description: Leaking flag through symbolic reg with angr
---

Archivo: [headerquery](/assets/posts/babytrace/headerquery)
Archivo: [pitas](/assets/posts/babytrace/pitas.py)
Servidor: babytrace.quals2019.oooverflow.io 
Puerto: 5000

<p style='text-align: justify;'>
El reto nos proporciona 3 archivos: un Dockerfile, headerquery y un script de python pitas.py que es el que se esta ejecutando en el servidor remoto.
</p>

![Menu principal]({{ '/assets/posts/babytrace/pitas_main.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Al conectarnos al servidor con netcat nos presenta con el contenido de pitas.py lo cual en primera instancia nos pide que seleccionemos un binario, false o headerquery,
una vez seleccionado el binario nos presenta una serie de opciones para comenzar, resumir o borrar un trace. Al optar por "start a trace" nos presenta otro menu donde nos pregunta 
como deseamos manejar el input del programa: unconstrained symbolic variable, constrained symbolic variable, concrete value. Como de entrada no sabemos que ocupamos optamos por agregar
una variable simbolica sin restricciones, en el siguiente menu podemos ver que tiene las opciones para ejecutar N pasos del programa, mostrar el input, mostrar output, mostrar error, 
concretar un registro, simbolizar un registro e imprimir las restricciones agregadas. Optamos por ejecutar 100 pasos para ver si marca algo y nos corta la conexion con el siguiente error:
</p>

```
Assertion violation: This is a tracing interface, not a general symbolic exploration client!!!
```

<p style='text-align: justify;'>
Lo cual al buscar en pitas.py vemos que tiene la siguiente restriccion:
</p>

```python
assert len(simgr.active) == 1, "This is a tracing interface, not a general symbolic exploration client!!!"
```

<p style='text-align: justify;'>
Dado que ejecutamos con angr y un input sin restricciones generara todas las ramas necesarias para explorar el programa por lo que debemos analizar el binario para ver de que manera 
podemos hacer que se ejecute sin generar mas de 1 estado activo.
</p>

![Headerquery]({{ '/assets/posts/babytrace/headerquery.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Como podemos observar las operaciones que realiza es abrir el archivo del flag, leer el contenido del flag (buf) y leer 4 bytes desde el input (var_118). Si el input es menor o igual a
0xFF el programa continua con la ejecucion por la rama de la derecha , posterior a ello imprime "Checking input..." y vuelve a compara nuestro input, si el mismo es mayor de 2 entonces
se va por la rama de la derecha imprimiendo "Nope." por el contrario si es menor o igual a 2 salta por la rama de la izquierda imprimiendo el byte que corresponde al indice de nuestro
input.
</p>

<p style='text-align: justify;'>
La cuestion es como obtener el flag si solo nos permite leer los 3 bytes de acuerdo a la logica del programa, la solución esta en 0x400856 antes de que valide por segunda ocasión el 
input.
</p>

```
mov eax,[rbp+var_118]
cdqe
movzx eax,[rbp+rax+buf] 
```

<p style='text-align: justify;'>
Como podemos observar antes de validar el input carga en eax el contenido del flag en el indice de nuestro input por lo que si podemos ejecutar hasta ese punto en rax tendriamos el byte
de ese offset.
</p>

<p style='text-align: justify;'>
Con lo anterior en mente podemos proceder a conectarnos al servidor, cargar el binario headerquery, agregar un valor en concreto(p.e.: 03000000), ejecutar 12 pasos (Opc. 1),
agregar un registro simbólico (Opc. 6, rax en este caso) e imprimir las restricciones (Opc. 7) para obtener el valor de rax con ese input como se puede observar al final de la siguiente 
imagen.
</p>

![Leak]({{ '/assets/posts/babytrace/leak.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Por lo que para obtener todo el flag podemos repetir la operacion tantas veces sea necesario hasta que obtengamos el caracter de fin del flag '}'. Para automatizar lo anterior se diseño
el siguiente script.
</p>

```python
from pwn import *
import re

result = ""
for i in range(0x30):
	r = remote('babytrace.quals2019.oooverflow.io', 5000)
	for j in range(49):
		r.recvline()
	r.recvn(8)
	r.sendline("2")
	r.sendline("1")
	r.sendline("3")
	v = ""
	if i < 0x10:
		v += "0"
	v += "%x" % i
	v += "000000"
	r.sendline(v)
	r.sendline("0")
	r.sendline("1")
	r.sendline("12")
	r.sendline("6")
	r.sendline("rax")
	r.sendline("7")
	pattern = re.compile(r'CONSTRAINTS:')
	s = r.recvline()
	f = re.search(pattern, s)
	while f == None:
		s = r.recvline()
		f = re.search(pattern, s)
	result += chr(int(s[28:32],0))
	r.close()
	if chr(int(s[28:32],0)) == '}':
		print result
		break
```

<p style='text-align: justify;'>
¿Como se obtuvo que se necesitaban 12 pasos para leer el flag? A prueba y error, ejecutando paso a paso y revisando el Output... en IDA observamos que la vulnerabilidad venia justo antes 
de que imprimiera "Checking input..." así que simplemente ejecute paso por paso hasta antes de que imprimiera el mensaje.
</p>
