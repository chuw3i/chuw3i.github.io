# 文章名


## realloc

```c
realloc(ptr,size)
1.ptr == 0 : malloc(size)
2.ptr != 0 &amp;&amp; size == 0 : free(ptr)
3.ptr != 0 &amp;&amp; size == old_size : edit(ptr)
3.ptr != 0 &amp;&amp; size &lt; old_size : edit(ptr) and free(remainder)
4.ptr != 0 &amp;&amp; size &gt; old_size : malloc(size);strcpy(new_ptr,ptr);free(ptr);return new_pt
```

## _nptl_change_stack_perm

_nptl_change_stack_perm 可用于设置栈的权限，目前在risc-v题的题目中见过


---

> 作者: chuwei  
> URL: https://chuw3i.github.io/posts/4a6e681/  

