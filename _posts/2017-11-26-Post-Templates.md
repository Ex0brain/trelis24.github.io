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


## Insert an image

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

## Headers
```
# H1
## H2
### H3
#### H4
##### H5
###### H6

Alternatively, for H1 and H2, an underline-ish style:

Alt-H1
======

Alt-H2
------
```

## Emphasis
```
Emphasis, aka italics, with *asterisks* or _underscores_.

Strong emphasis, aka bold, with **asterisks** or __underscores__.

Combined emphasis with **asterisks and _underscores_**.

Strikethrough uses two tildes. ~~Scratch this.~~
```

## Quotes
```
> Blockquotes are very handy in email to emulate reply text.
> This line is part of the same quote.

Quote break.

> This is a quote
```

## Youtube videos
They can't be added directly but you can add an image with a link to the video like this:
```
<a href="http://www.youtube.com/watch?feature=player_embedded&v=YOUTUBE_VIDEO_ID_HERE
" target="_blank"><img src="http://img.youtube.com/vi/YOUTUBE_VIDEO_ID_HERE/0.jpg" 
alt="IMAGE ALT TEXT HERE" width="240" height="180" border="10" /></a>
```
Or, in pure Markdown, but losing the image sizing and border:
```
[![IMAGE ALT TEXT HERE](http://img.youtube.com/vi/YOUTUBE_VIDEO_ID_HERE/0.jpg)](http://www.youtube.com/watch?v=YOUTUBE_VIDEO_ID_HERE)
```