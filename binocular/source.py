import tree_sitter_c
import tree_sitter
from tree_sitter import Language, Parser


def walk(root: tree_sitter.Node):
    cursor = root.walk()

    visited_children = False
    while True:
        if not visited_children:
            print(cursor.node.type, cursor.node.text)
            yield cursor.node
            if not cursor.goto_first_child():
                visited_children = True
        elif cursor.goto_next_sibling():
            visited_children = False
        elif cursor.goto_parent():
            break


def find_type(root: tree_sitter.Node, type: str, all: bool = False):
    nodes = list()

    for node in walk(root):
        # print(node.type, type, node.type == type)
        if node.type == type:
            if all:
                nodes.append(node)
            else:
                return node

    if all:
        return nodes

    return None


def get_child_by_type(root: tree_sitter.Node, *types):
    for child in root.children:
        if child.type in types:
            return child
    return None


def traverse(root, *types):
    n = root
    for t in types:
        n = get_child_by_type(n, t)
        if n is None:
            return None
    return n


def unwind_ptr(root):
    assert root.type == 'pointer_declarator'
    node = root
    ptr_count = 1

    while (next_node := get_child_by_type(node, 'pointer_declarator')) is not None:
        ptr_count += 1
        node = next_node

    return node, ptr_count


class C_Code:
    lang = Language(tree_sitter_c.language())

    @classmethod
    def find_func(cls, function_name: str, source_code: bytes, encoding: str = 'utf8') -> tree_sitter.Node:
        '''Searches for the function definition node in tree sitter by function name'''
        parser = Parser(cls.lang)
        tree = parser.parse(source_code)
        root = tree.root_node

        for node in root.children:
            if node.type != "function_definition":
                continue

            name = cls.get_name(node)
            if name == function_name:
                return node

        return None

    @staticmethod
    def get_name(func_def, encoding: str = 'utf8'):
        
        next_n = get_child_by_type(func_def, 'pointer_declarator')
        if next_n is None:
            next_n = func_def
        else:
            next_n, _ = unwind_ptr(next_n)

        func_dec = get_child_by_type(next_n, "function_declarator")

        # Unable to find function_declarator
        if func_dec is None:
            return None

        id_node = get_child_by_type(func_dec, 'identifier')
        if id_node is not None:
            return str(id_node.text, encoding=encoding)
        else:
            func_sig = get_child_by_type(func_dec, 'parenthesized_declarator')
            next_n = get_child_by_type(func_sig, 'pointer_declarator')
            if next_n is None:
                next_n = func_sig
            else:
                next_n, _ = unwind_ptr(next_n)

            id_node = traverse(next_n, 'function_declarator', 'identifier')
            return str(id_node.text, encoding=encoding)

    @staticmethod
    def normalize(func_def: tree_sitter.Node, encoding: str = 'utf8'):
        '''
        This is a cluster fuck; sorry.
        '''
        # name
        next_n = get_child_by_type(func_def, 'pointer_declarator')
        if next_n is None:
            ret_ptr_count = 0
            next_n = func_def
        else:
            next_n, ret_ptr_count = unwind_ptr(next_n)
        fptr_ret_count = ret_ptr_count

        func_dec = get_child_by_type(next_n, "function_declarator")
        id_node = get_child_by_type(func_dec, 'identifier')

        # Qualifiers - Mix of both storage-class specifiers and type qualifiers
        qualifiers = list()

        # C11 Standard 6.7.1 - At most one storage-class specifier may be given in the declaration specifier (except _Thread_local
        # can appear with static or extern) storage class specifiers: typedef, extern, static, _Thread_local, auto, register

        # C11 Standard 6.7.3 - Type Qualifiers: const, restrict, volatile, _Atomic (_Atomic can not be used with a function type)

        for child in func_def.children:
            if child.type == "storage_class_specifier" or child.type == "type_qualifier":
                qualifiers.append(str(child.text, encoding=encoding))

        fptr_ret = False
        if id_node is not None:
            name = str(id_node.text, encoding=encoding)
        else:
            fptr_ret = True
            func_sig = get_child_by_type(func_dec, 'parenthesized_declarator')
            next_n = get_child_by_type(func_sig, 'pointer_declarator')
            if next_n is None:
                ret_ptr_count = 0
                next_n = func_sig
            else:
                next_n, ret_ptr_count = unwind_ptr(next_n)
            id_node = traverse(next_n, 'function_declarator', 'identifier')
            name = str(id_node.text, encoding=encoding)

        # Arguments
        if fptr_ret:
            func_sig = get_child_by_type(func_dec, 'parenthesized_declarator')
            next_n = get_child_by_type(func_sig, 'pointer_declarator')
            if next_n is None:
                ret_ptr_count = 0
                next_n = func_sig
            else:
                next_n, ret_ptr_count = unwind_ptr(next_n)

            param_list = traverse(
                next_n, 'function_declarator', 'parameter_list')
        else:
            param_list = get_child_by_type(func_dec, 'parameter_list')

        if param_list is None:
            raise ValueError("Cannot find parameters")

        arguments = list()
        for param_dec in [node for node in param_list.children if node.type == "parameter_declaration"]:
            # Argument Name
            next_n = get_child_by_type(param_dec, 'pointer_declarator')
            if next_n is None:
                next_n = param_dec
                ptr_count = 0
            else:
                next_n, ptr_count = unwind_ptr(next_n)

            data_type_node = get_child_by_type(
                param_dec, "primitive_type", "sized_type_specifier", "struct_specifier", "type_identifier")
            if data_type_node is None and param_dec.type == 'variadic_parameter':
                arguments.append(dict(var_args=True))
                continue
            else:
                data_type = str(data_type_node.text,
                                encoding=encoding) + "*"*ptr_count

            param_func_dec = get_child_by_type(next_n, 'function_declarator')

            # Three Cases for Parameters #
            # 1. Function Pointer
            # 2. Variadic
            # 3. A Normal looking one
            if param_func_dec is not None:
                func_sig = get_child_by_type(
                    param_func_dec, 'parenthesized_declarator')
                next_n = get_child_by_type(func_sig, 'pointer_declarator')
                if next_n is None:
                    next_n = func_sig
                    param_ptr_count = 0
                else:
                    next_n, param_ptr_count = unwind_ptr(next_n)

                param = get_child_by_type(next_n, "identifier")
                param_name = str(param.text, encoding=encoding)

                fptr_params = str(get_child_by_type(
                    param_func_dec, "parameter_list").text, encoding=encoding)
                arguments.append(dict(
                    data_type=f"{data_type}({'*'*param_ptr_count}){fptr_params}",
                    var_name=param_name,
                    is_func_ptr=True
                ))

            # This check is probably unneeded because of the above variadic_parameter
            elif (param := get_child_by_type(next_n, 'variadic_parameter')):
                arguments.append(dict(var_args=True))
            else:
                param = get_child_by_type(
                    next_n, "identifier", 'array_declarator')

                if param is None:
                    # No name is provided. This is probably a prototype
                    # But we will place a special case check for a parameter of just 'void' (no * i.e. not a pointer type)
                    if data_type_node.text == b'void' and ptr_count == 0:
                        # Skip this argument
                        continue
                    else:
                        # Prototype??
                        param_name = ""
                else:
                    param_name = str(param.text, encoding=encoding)

                arguments.append(dict(
                    data_type=data_type,
                    var_name=param_name
                ))

        # Return Type
        ret_node = get_child_by_type(
            func_def, "primitive_type", "sized_type_specifier", "struct_specifier", "type_identifier")
        if fptr_ret:
            next_n = get_child_by_type(func_def, 'pointer_declarator')
            if next_n is None:
                next_n = func_def
            else:
                next_n, _ = unwind_ptr(next_n)

            fptr_ret_node = traverse(
                next_n, "function_declarator", 'parameter_list')
            ret = f"{str(ret_node.text, encoding=encoding)}{'*'*fptr_ret_count}({'*'*ret_ptr_count}){str(fptr_ret_node.text, encoding=encoding)}"
        else:
            ret_node = get_child_by_type(
                func_def, "primitive_type", "sized_type_specifier", "struct_specifier", "type_identifier")
            ret = str(ret_node.text, encoding=encoding)

        return dict(
            lang="C",
            name=name,
            source=str(get_child_by_type(
                func_def, 'compound_statement').text, encoding=encoding),
            argv=arguments,
            return_type=f"{ret}{'*'*(0 if fptr_ret else ret_ptr_count)}",
            qualifiers=qualifiers
        )
