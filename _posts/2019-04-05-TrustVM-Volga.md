---
layout: post
title: "TrustVM - Volga 19"
date: 2019-04-02 22:27:00
tags: CTFWriteup Reversing Volga Stripped
description: VolgaCTF 2019, Categoria RE
---

Archivo: [reverse](/assets/posts/trustvm/reverse)
Archivo: [encrypt](/assets/posts/trustvm/encrypt)
Archivo: [data.enc](/assets/posts/trustvm/data.enc)

```
IDA BaseAddress: 0x559ABDA9C000
```

<p style='text-align: justify;'>
El reto nos proporciona 3 archivos: reverse, encrypt y data.enc, los cuales procedemos a identificar con el comando file
</p>


```
$ file reverse
reverse: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
 for GNU/Linux 3.2.0, BuildID[sha1]=3bb92ab13d6ca2aa28eed5a2eefaf48db71975a7, stripped
```

```
$ file encrypt
encrypt: data
```

```
$ file data.enc
data.enc: data
```

<p style='text-align: justify;'>
Como podemos ver el único ejecutable es el archivo reverse, al intentar ejecutarlo nos da la ayuda.
</p>

```
Usage:
        ./reverse progname filetoprocess
```

<p style='text-align: justify;'>
Con lo cual podemos asumir que encrypt es progname y data.enc es el resultado de correr dicho programa a un archivo, por lo que procedemos
a crear un archivo de texto "test" con el contenido: VolgaCTF{0123456789ancdef} para probar el funcionamiento del programa y tratar de
analizar que es lo que hace mediante un análisis dinámico. 
</p>

<p style='text-align: justify;'>
Dado que son archivos con lo que se esta trabajando podemos buscar entre las funciones referencias a fopen y encontramos 2 referencias, una dentro de una funcion
que recibe por parametro el archivo que va a abrir y proceder a hacer todo el proceso de lectura del archivo y cerrado del mismo, esta función la renombramos como open_file.
</p>

![open_file]({{ '/assets/posts/trustvm/fopen.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
La 2da referencia que encontramos es donde se abre un archivo en modo escritura binaria y el nombre del archivo corresponde a %s.enc, si recordamos uno de los archivos que se
nos proporciono fue data.enc por lo que podemos asumir que este es el lugar donde finaliza la ejecución del programa y se crea el archivo cifrado.
</p>

![open_file_enc]({{ '/assets/posts/trustvm/fopen_enc.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Regresando a la funcion que renombramos como open_file, buscamos las referencias a las mismas para saber desde donde las manda llamar y encontramos 2 referencias que estan una tras otra
por lo que podemos suponer que lee el archivo correspondiente al programa y el archivo a cifrar. Lo cual confirmamos al revisar el valor de rax despues de la segunda lectura ya que apunta
a una dirección del heap donde inicia el contenido de nuestro archivo.
</p>

![heap_init]({{ '/assets/posts/trustvm/heap_init.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Una vez teniendo la dirección donde carga el input, en este caso 0x5605C48704E0, podemos proceder a recorrer el programa paso a paso hasta encontrar donde se hace referencia 
a dicha dirección para poder analizar que es lo que hace con el contenido del archivo. Sin embargo observando el grafíco de la función vemos que es bastante grande y con varios ciclos
de por medio por lo que nos tomara algo de tiempo localizarlo por lo que podemos optar por correr un simple script que realice step over hasta que encuentre una referencia a la 
dirección en cuestion en uno de los registros o hasta que llegue al final, podemos considerar 0x556ED54B3B20 como el final ya que es donde escribe el archivo .enc.
</p>

![main_graph]({{ '/assets/posts/trustvm/graph_overview.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Observando el grafíco de la función vemos que es bastante grande y con varios ciclos de por medio por lo que nos tomara algo de tiempo localizarlo por lo que podemos 
optar por correr un script que realice step over hasta que encuentre una referencia a la dirección en cuestion en uno de los registros o hasta que llegue al final, 
podemos considerar 0x556ED54B3B20 como el final ya que es donde escribe el archivo ".enc".
</p>

```python
import idaapi

dirs = [0x556ED54B3B20,__ADDR__INPUT__]

registros_lbl = ['RAX','RBX','RCX','RDX','RSI','RDI','RIP']
registros = []
for lbl in registros_lbl:
	registros.append(idaapi.regval_t())
	idaapi.get_reg_val(lbl,registros[-1])

found = False
while found == False :
	idaapi.step_over()
	GetDebuggerEvent(WFNE_SUSP, -1) 
	for i in range(len(registros)):
		registro = registros[i]
		try:
			dirs.index(registro.ival)
			found = True
			break
		except ValueError:
			idaapi.get_reg_val(registros_lbl[i],registros[i])
```

<p style='text-align: justify;'>
El script hay que correrlo un par de veces, o hasta después de la dirección 0x556227A4AA3D, para que se ejecute por un par de minutos y encuentre el siguiente bloque donde se hace
una copia del contenido donde originalmente lo cargo a otra ubicación en el heap 0x556227C4C280, por lo que en este punto es conveniente modificar nuestro script para incluir
dicha dirección y ejecutar nuevamente el script.
</p>

![rdx_to_rax]({{ '/assets/posts/trustvm/rdx_to_rax.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Después de correrlo nuevamente nos llevara a otro bloque ubicado en 0x556227A4ACB0 donde podemos observar como va cargando nuestro input, RDX, en los registros XMM, hace XOR de 
los mismos contra el contenido al que apunta RAX y el resultado de la operacion lo almacena en [r12+rsi] = 0x56062B1E240 por lo que nuevamente tomamos nota de dicha dirección y 
procedemos agregarla a nuestro script para continuar con el análisis.
</p>

![xor_input]({{ '/assets/posts/trustvm/xor_input.png' | relative_url }}){: .center-image }

![0x5576C1AC2240]({{ '/assets/posts/trustvm/0x5576C1AC2240.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Con la ejecución anterior nuestro script nos llevara hasta 0x56062BA1CC85 ya que cargara en rax = 0x56062B1E240, sin embargo en este punto es demasiado tarde ya que si observamos
el contenido de la dirección podemos ver que no coincide con lo que anteriormente teniamos grabado en dicha ubicación por lo que en algún momento entre el paso anterior y este
se modificaron los valores
</p>

![0x5576C1AC2240_2]({{ '/assets/posts/trustvm/0x5576C1AC2240_2.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
Al analizar la ejecución en ese punto podemos observar que la dirección de nuestro registro se encuentra en R11 y R8 ademas de RAX, y podemos observar que el bloque actual de
ejecución proviene de un ciclo que inicia en 0x5576C18C0C48. A simple vista podemos ver que carga un byte de nuestro input cifrado en eax y otro en edx, lo anterior lo deducimos
dado que R11 y R8 apuntan a nuestro input, solo necesitariamos saber el valor de RDI y RDX que actuan como offsets para determinar de que manera accede a nuestro input.
</p>

![swap]({{ '/assets/posts/trustvm/swap.png' | relative_url }}){: .center-image }

![clea_esi]({{ '/assets/posts/trustvm/clean_esi.png' | relative_url }}){: .center-image }

<p style='text-align: justify;'>
De la imagen anterior podemos observar lo siguiente: edi/rdi se inicializa a 0 en 0x5576C18C0C17, en cada iteración rdi se incrementa en 1 y el ciclo termina cuando rdi == 0x40, 
edx = (rdi + 0x3f) & 0x3f. Lo anterior nos daria como resultado que edx apunta al byte anterior al que apunta RDI y lleva a cabo unas operaciones de shl,shr y or con ambos bytes
para volverlos a almacenar de ahí que nuestro input estuviera modificado, solo nos faltaría determinar el valor de CL y R9 ya que con CL realiza las 2 primeras operaciones de shl
y r9 actua como offset para almacenar los valores. Por lo que para tratar de darnos una idea de que esta realizando procedemos a poner un breakpoint en 0x5576C18C0C48 y 
reiniciamos la ejecucion pero esta vez en lugar de rastrear el input ejecutamos con F9 para que el programa llegue a este ese punto y podemos observar que CL = 5 y R9 = 9. 
Adicionalmente ponemos un breakpoint en 0x556ED54B3B20 que es donde habiamos determinado que estaba el final del programa para ver en que momento crea el archivo.
</p>

<p style='text-align: justify;'>
Al continuar con la ejecución podemos observar que nuevamente se accede a dicho ciclo pero en esta ocasion R8 y R11 apuntan al xorkey utilizada previamente y lleva a cabo la misma
operación que con nuestro input cifrado pero CL=7 y R9=0xD. Posterior a esto podemos continuar con nuestro análisis, ya sea paso a paso o con el script agregando direcciones que nos
parescan interesantes para ver en que momento trabaja con ellas, sin embargo dado que el input que ingresamos es de longitud <=0x40 el programa procedera a generar el archivo .enc
con el contenido que se encuentra en 0x56062B1E240.
</p>

<p style='text-align: justify;'>
En este punto podemos determinar lo siguiente: 
</p>

	1. Lectura de 0x40 bytes
	
	2. Procede a realizar una operación XOR contra una llave previamente calculada, 
	   independiente del input.
	
	3. Operaciones SHL,SHR y OR entre los bytes del input, CL=5 y R9 = 9
	
	4. Modificacion de la llave XOR utilizada en el 2do punto de acuerdo a las operaciones del 
	   punto anterior pero CL=7 y R9=0xD
	
	5. Intenta leer otros 0x40 bytes y si hay mas datos vuelve al punto #2 sino procede a 
	   escribir el archivo

<p style='text-align: justify;'>	
Con lo anterior en mente podemos codificar un script en python que nos permita emular el programa encrypt. Aunque para el correcto funcionamiento requerimos extraer la llave XOR usada
en el binario, para lo cual podemos hacerlo manual o buscar algun script de IDA que nos permita extraerlo.
</p>

```python
with open("reverse_xorkey.bin", "rb") as f:
	xorkey = f.read(0x40)

res = ""
with open("archivo", "rb") as f:
	finput = f.read(0x40)
	while len(finput.strip())>0:
		inputxor = ""
		for i in range(0x40):
			inputxor += chr(( ord(finput[i]) if i<len(finput) else 0) ^ ord(xorkey[i]))
		tmp = list(" "*0x40)
		j = 9
		cl = 5
		for i in range(0x40):
			rax = ord(inputxor[i])
			rdx = ord(inputxor[i-1])
			rax <<= cl
			rdx <<= cl
			rdx >>=8
			rdx |= rax
			rdx &= 0xFF #just 1 byte
			tmp[j%0x40] = chr(rdx)
			j+=1
		
		
		res += "".join(tmp)
		cl = 7
		tmp = list(" "*0x40)
		j = 0xD # j+=4
		for i in range(0x40):
			rax = ord(xorkey[i])
			rdx = ord(xorkey[i-1])
			rax <<= cl
			rdx <<= cl
			rdx >>=8
			rdx |= rax
			rdx &= 0xFF #just 1 byte
			tmp[j%0x40] = chr(rdx)
			j+=1
		
		xorkey = "".join(tmp)
		tmp = ""
		for i in range(0x40):
			tmp += chr(( ord(finput[i]) if i<len(finput) else 0) ^ ord(xorkey[i]))
			
		xorkey = tmp
		finput = f.read(0x40)

with open("archivo.enc", "wb") as f:
	f.write(res)

```

<p style='text-align: justify;'>
Si ejecutamos nuestro script y el programa encrypt sobre el mismo archivo podemos observar que generan la mismas salida por lo que solo requerimos codificar un script que actue de 
manera inversa para la parte de cifrado del input y aplicarlo a data.enc para obtener el flag.
</p>

<p style='text-align: justify;'>
El script de solución quedo de la siguiente manera:
</p>

```python
def fix_hex(_hex):
	if len(_hex)==3:
		_hex = _hex[0:2]+"0"+_hex[2:3]
	return _hex

with open("reverse_xorkey.bin", "rb") as f:
	xorkey = f.read(0x40)

finput = ""
fname = "data"
with open(fname+".enc", "rb") as f:
	inputxor = f.read(0x40)
	while len(inputxor.strip())>0:
		j = 9
		cl = 5
		tres = list(" "*0x40)
		for i in range(0x40):
			tmp = fix_hex(hex(ord(inputxor[(i+j)%0x40])))
			tmp1 = fix_hex(hex(ord(inputxor[(i+j+1)%0x40])))
			rax = list("0x0000")
			rax[2] = str(int(tmp1[0:3],0)%2)
			rax[3] = tmp1[3]
			if int(tmp[0:3],0)%2 == 0:
				rax[4] = tmp[2]
			else:
				rax[4] = hex(int(tmp[0:3],0)-1)[2]
			
			tres[i] = chr(int("".join(rax),0)>>5)
		
		res = ""
		for i in range(0x40):
			res += chr(ord(tres[i])  ^ ord(xorkey[i]))
					
		finput += res
		cl = 7 
		tmp = list(" "*0x40)
		j = 0xD
		for i in range(0x40):
			rax = ord(xorkey[i])
			rdx = ord(xorkey[i-1])
			rax <<= cl
			rdx <<= cl
			rdx >>=8
			rdx |= rax
			rdx &= 0xFF #just 1 byte
			tmp[j%0x40] = chr(rdx)
			j+=1
		
		xorkey = "".join(tmp)
		tmp = ""
		for i in range(0x40):
			tmp += chr(( ord(res[i]) if i<len(res) else 0) ^ ord(xorkey[i]))
		
		xorkey = tmp
		inputxor = f.read(0x40)

with open(fname, "wb") as f:
	f.write(finput)
```
<p style='text-align: justify;'>
Una vez ejecutado el script anterior podemos abrir el archivo resultante y vemos que tiene los magic bytes de un archivo PNG por lo que basta con cambiar la extensión para tener el flag.
</p>


