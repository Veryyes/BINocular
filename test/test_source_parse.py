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
