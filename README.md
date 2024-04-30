# UdonSharpIDAP
IDA Processor for UdonSharp

I have always wanted to implement features like graph view and cross-reference in my UdonDisassembler so that I can better understand what the code does.

If you're just looking at some simple functions, that's fine, you can just read small snippets to understand what's going on. But once you hit the massive amount of code a large map has, it's hell.

So why not just use IDA? One of my most familiar tools and it already has all the features I need. Now here it is.

![ida](https://raw.githubusercontent.com/UdonSharpRE/UdonSharpIDAP/main/images/ida64.png)

# NB
This is not a complete product, since I have 0 knowledge about IDA APIs, and personally I think the documentation and examples of IDA are not perfect enough, which adds a lot of understanding cost, it is currently only a very, very early version, it can't even understand one function, currently all it can do is disassemble a single instruction when you press C, and generate cross-references to the JUMP and JUMP_IF_FALSE (aka JNE) instructions. I also created a segment for Udon's heap and put all the All references to heap are redirected to that place.

I may continue to improve this processor in the future. Also hoping someone can read this and help me finish this processor.
