from binocular import SourceFunction

def test_c_func1():
    # more than one parameter
    f = b'int bar(char c, int x, long* a){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'int'
    
    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'
    assert src.argv[1].data_type == 'int'
    assert src.argv[1].var_name == 'x'
    assert src.argv[2].data_type == 'long*'
    assert src.argv[2].var_name == 'a'

def test_c_func2():
    # parameter is a single pointer
    f = b'long bar(char *c){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'long'

    assert src.argv[0].data_type == 'char*'
    assert src.argv[0].var_name == 'c'

def test_c_func3():
    # parameter is a double pointer
    f = b'uint32_t bar(char **c){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'uint32_t'

    assert src.argv[0].data_type == 'char**'
    assert src.argv[0].var_name == 'c'

def test_c_func4():
    # parameter is a struct
    f = b'short bar(struct poggers p){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'short'

    assert src.argv[0].data_type == 'struct poggers'
    assert src.argv[0].var_name == 'p'

def test_c_func5():
    # paramater is a triple pointer to a struct
    f = b'char* bar(struct poggers ***p){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'char*'

    assert src.argv[0].data_type == 'struct poggers***'
    assert src.argv[0].var_name == 'p'

def test_c_func6():
    # parameter is an array with a known/defined size
    f = b'int bar(char a[1][2]){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'int'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'a[1][2]'

def test_c_func7():
    # parameter is a pointer to an array with a known/defined size
    f = b'int bar(char *a[1][2]){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'int'

    assert src.argv[0].data_type == 'char*'
    assert src.argv[0].var_name == 'a[1][2]'

def test_c_func8():
    # return type is a double void pointer
    f = b'void ** bar(char c){return &malloc(5);}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return &malloc(5);}'
    assert src.return_type == 'void**'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func9():
    # return type is a struct
    f = b'struct socket bar(char c){return 0;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 0;}'
    assert src.return_type == 'struct socket'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func10():
    # return type is a double struct pointer
    f = b'struct socket** bar(char c){return 0;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 0;}'
    assert src.return_type == 'struct socket**'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func11():
    # return type is a quintuple struct pointer
    f = b'struct socket *****bar(char c){return 0;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 0;}'
    assert src.return_type == 'struct socket*****'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func12():
    # return type is a function pointer 
    f = b'float (*foo(char c))(int, short){return bar;}'
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return bar;}'
    assert src.return_type == 'float(*)(int, short)'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func13():
    # return type is a double function pointer
    f = b'float (**foo(char c))(int, short){return &bar;}'
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return &bar;}'
    assert src.return_type == 'float(**)(int, short)'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func14():
    # return type is a function pointer that points to a function that returns a struct
    f = b'struct socket (*foo(char c))(int, short){return bar;}'
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return bar;}'
    assert src.return_type == 'struct socket(*)(int, short)'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func15():
    # return type is a function pointer that points to a function that returns a double pointer to a struct
    f = b'struct socket** (*foo(char c))(int, short){return bar;}'
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return bar;}'
    assert src.return_type == 'struct socket**(*)(int, short)'

    assert src.argv[0].data_type == 'char'
    assert src.argv[0].var_name == 'c'

def test_c_func16():
    # return type is a function pointer that points to a function that returns a double pointer to a struct
    # and the parameter of the function is a struct
    f = b'struct socket** (*foo(struct socket s))(int, short){return bar;}'
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return bar;}'
    assert src.return_type == 'struct socket**(*)(int, short)'

    assert src.argv[0].data_type == 'struct socket'
    assert src.argv[0].var_name == 's'

def test_c_func17():
    # return type is a function pointer that points to a function that returns a double pointer to a struct
    # and the parameter of the function is a double pointer to a struct
    f = b'struct socket** (*foo(struct socket **s))(int, short){return bar;}'
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return bar;}'
    assert src.return_type == 'struct socket**(*)(int, short)'

    assert src.argv[0].data_type == 'struct socket**'
    assert src.argv[0].var_name == 's'

def test_c_func18():
    # parameter of function is a function pointer
    f = b'long bar(float (*callback)(char*)){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'long'

    assert src.argv[0].data_type == 'float(*)(char*)'
    assert src.argv[0].var_name == 'callback'

def test_c_func19():
    # parameter of function is a double function pointer
    f = b'long bar(float (**callback)(char*)){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'long'

    assert src.argv[0].data_type == 'float(**)(char*)'
    assert src.argv[0].var_name == 'callback'

def test_c_func20():
    # parameter of function is a double function pointer
    f = b'long bar(float (**callback)(char*), struct socket* s){return 1;}'
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.source == '{return 1;}'
    assert src.return_type == 'long'

    assert src.argv[0].data_type == 'float(**)(char*)'
    assert src.argv[0].var_name == 'callback'
    assert src.argv[1].data_type == 'struct socket*'
    assert src.argv[1].var_name == 's'

def test_c_func21():
    # function with no parameters
    f = b"float foo(){return 3.14;}"
    src = SourceFunction.from_code("foo", f)

    assert src.name == 'foo'
    assert src.source == '{return 3.14;}'
    assert src.return_type == 'float'

    assert len(src.argv) == 0
    
def test_c_func22():
    f = b"extern\tvoid\nregsub9(char *sp,\t/* source string */\n\tchar *dp,\t/* destination string */\n\tint dlen,\n\tResub *mp,\t/* subexpression elements */\n\tint ms)\t\t/* number of elements pointed to by mp */\n{//removed}"
    src = SourceFunction.from_code("regsub9", f)

    assert src.name == "regsub9"
    assert src.return_type == "void"

    assert "extern" in src.qualifiers

    assert src.argv[0].data_type == "char*"
    assert src.argv[0].var_name == "sp"
    assert src.argv[1].data_type == "char*" 
    assert src.argv[1].var_name == "dp"
    assert src.argv[2].data_type == "int"
    assert src.argv[2].var_name == "dlen"
    assert src.argv[3].data_type == "Resub*"
    assert src.argv[3].var_name == "mp"
    assert src.argv[4].data_type == "int"
    assert src.argv[4].var_name == "ms"

def test_c_func23():
    f = b"unsigned int bar(){return 5;}"
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.return_type == 'unsigned int'

def test_c_func24():
    f = b"volatile int bar(){}"
    src = SourceFunction.from_code("bar", f)

    assert src.name == 'bar'
    assert src.return_type == 'int'

    assert "volatile" in src.qualifiers

def test_c_func25():
    f = b"extern const volatile int foo(){}"
    src = SourceFunction.from_code("foo", f)
    assert src.name == 'foo'
    assert src.return_type == 'int'

    assert len(set(["extern", "const", "volatile"]) ^ src.qualifiers) == 0

def test_c_func26():
    # Decompiled code from Ghidra
    # Though still human readable as a function, its not tenable to try to 
    # robustly parse through decompiler input as it is not always proper C
    f = b'caseD_96(void)\n\n{\n  undefined4 *puVar1;\n  SSL *pSVar2;\n  undefined4 uVar3;\n  undefined4 uVar4;\n  undefined4 *unaff_r6;\n  SSL *unaff_r10;\n  \n  puVar1 = (undefined4 *)BIO_get_data();\n  SSL_free((SSL *)puVar1[4]);\n  pSVar2 = SSL_dup(unaff_r10);\n  uVar3 = unaff_r6[5];\n  uVar4 = unaff_r6[2];\n  puVar1[3] = unaff_r6[3];\n  puVar1[4] = pSVar2;\n  if (pSVar2 != (SSL *)0x0) {\n    pSVar2 = (SSL *)0x1;\n  }\n  puVar1[2] = uVar4;\n  uVar4 = unaff_r6[1];\n  *puVar1 = *unaff_r6;\n  puVar1[1] = uVar4;\n  puVar1[5] = uVar3;\n  return pSVar2;\n}'
    src = SourceFunction.from_code("caseD_96", f)

    assert src is None