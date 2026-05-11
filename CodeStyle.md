# Code Style Guide

## C++

| Element | Convention | Example |
|---------|-----------|---------|
| Variables | camelCase | `bufferSize` |
| Private member variables | camelCase prefixed with `_` | `_bufferSize` |
| Functions / methods | camelCase | `getBufferSize()` |
| Classes / structs | CamelCaps | `BufferManager` |
| Constants / macros | UPPER_SNAKE_CASE | `MAX_BUFFER_SIZE` |


## Formatting

### Indentation & Line Length

Use **4 spaces** per indent level (no tabs). Lines should stay under **120 characters**. Access modifiers (`public:`, `private:`, `protected:`) sit at the same level as the `class` keyword, not indented with the class body:

```cpp
class Foo {
public:
    void bar();
private:
    int _x;
};
```

### Braces

Short single-statement blocks may stay on one line; inline functions may as well. Enums always use multiple lines, even when short.

### Function Parameters

If arguments don't fit on a single line, each one gets its own indented line (block-indent style). Never wrap all arguments to the next line as a group, and never cram multiple arguments on a continuation line:

```cpp
// correct
someFunction(
    firstArgument,
    secondArgument,
    thirdArgument
);

// wrong — don't cram
someFunction(firstArgument, secondArgument,
    thirdArgument);
```

### Templates

No space between `template` and `<`. The template declaration always lives on its own line, separate from the function or class it decorates:

```cpp
template<typename T>
void process(T value);
```

Ternary expressions break **after** `?`, keeping the condition on its own line:

```cpp
return condition
    ? valueIfTrue
    : valueIfFalse;
```

---

## C

| Element | Convention | Example |
|---------|-----------|---------|
| Variables / Arguments | snake_case | `buffer_size` |
| Functions | camelCase | `getBufferSize()` |
| Constants / macros | UPPER_SNAKE_CASE | `MAX_BUFFER_SIZE` |
| Namespaces / prefixes | snake_case, separated by `_` | `privmx_crypto_` |
