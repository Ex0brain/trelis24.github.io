---
layout: post
title:  "Posts Template"
categories: Blog
tags:  Template
author: Trelis
---

* content
{:toc}

Some templates I can use when I am doing my posts.

## Code

```js
/**
 * This function does something
 * @param  {String} fileName param1
 * @param  {String} content  param2
 */
function createAndDownloadFile(fileName, content) {
    var aTag = document.createElement('a');
    var blob = new Blob([content]);
    aTag.download = fileName;
    aTag.href = URL.createObjectURL(blob);
    aTag.click();
    URL.revokeObjectURL(blob);
}
```


## Inster an image

![](https://img.alicdn.com/tfs/TB16.GnOpXXXXXdapXXXXXXXXXX-307-134.png)


## Insert tags between text

In order to add tags, the text must be between `: `size` and `type` 

## Insert links

The text of the link goes between brackets and the url between parentheses: [ The Blob Interface and Binary Data](https://www.w3.org/TR/2015/WD-FileAPI-20150421/#blob)

## Lists

Lists are easy:
- Thing 1
- Thing 2

* Thing 3
* Thing 4

