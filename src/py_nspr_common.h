/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

//#define DEBUG

#define PACKAGE_NAME "nss"

typedef PyObject *(*format_lines_func)(PyObject *self, PyObject *args, PyObject *kwds);

typedef enum RepresentationKindEnum {
    AsObject,
    AsString,
    AsTypeString,
    AsTypeEnum,
    AsLabeledString,
    AsEnum,
    AsEnumName,
    AsEnumDescription,
    AsIndex,
    AsDottedDecimal,
} RepresentationKind;


#ifndef MIN
#define MIN(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

#define NSS_THREAD_LOCAL_KEY "nss"

#define PyBoolAsPRBool(x) ((x) == Py_True ? PR_TRUE : PR_FALSE)

#define ASSIGN_REF(dst, obj)                    \
do {                                            \
    PyObject *tmp;                              \
                                                \
    tmp = (PyObject *)dst;                      \
    Py_INCREF(obj);                             \
    dst = obj;                                  \
    Py_CLEAR(tmp);                              \
} while (0)

#define ASSIGN_NEW_REF(dst, obj)                \
do {                                            \
    PyObject *tmp;                              \
                                                \
    tmp = (PyObject *)dst;                      \
    dst = obj;                                  \
    Py_CLEAR(tmp);                              \
} while (0)


/******************************************************************************/

#define OCTETS_PER_LINE_DEFAULT 16
#define HEX_SEPARATOR_DEFAULT ":"

#define FMT_OBJ_AND_APPEND(dst_fmt_tuples, label, src_obj, level, fail) \
{                                                                       \
    PyObject *fmt_tuple = NULL;                                         \
                                                                        \
    if ((fmt_tuple = line_fmt_tuple(level, label, src_obj)) == NULL) {  \
        goto fail;                                                      \
    }                                                                   \
    if (PyList_Append(dst_fmt_tuples, fmt_tuple) != 0) {                \
        Py_DECREF(fmt_tuple);                                           \
        goto fail;                                                      \
    }                                                                   \
}

#define FMT_LABEL_AND_APPEND(dst_fmt_tuples, label, level, fail)        \
{                                                                       \
    PyObject *fmt_tuple = NULL;                                         \
                                                                        \
    if ((fmt_tuple = fmt_label(level, label)) == NULL) {                \
        goto fail;                                                      \
    }                                                                   \
    if (PyList_Append(dst_fmt_tuples, fmt_tuple) != 0) {                \
        Py_DECREF(fmt_tuple);                                           \
        goto fail;                                                      \
    }                                                                   \
}

#define APPEND_LINE_TUPLES_AND_CLEAR(dst_fmt_tuples, src_fmt_tuples, fail) \
{                                                                       \
    PyObject *src_obj;                                                  \
    Py_ssize_t len, i;                                                  \
    if (src_fmt_tuples) {                                               \
        len = PyList_Size(src_fmt_tuples);                              \
        for (i = 0; i < len; i++) {                                     \
            src_obj = PyList_GetItem(src_fmt_tuples, i);                \
            PyList_Append(dst_fmt_tuples, src_obj);                     \
        }                                                               \
        Py_CLEAR(src_fmt_tuples);                                       \
    }                                                                   \
}

#define APPEND_LINES_AND_CLEAR(dst_fmt_tuples, src_lines, level, fail)  \
{                                                                       \
    PyObject *src_obj;                                                  \
    Py_ssize_t len, i;                                                  \
    if (src_lines) {                                                    \
        len = PySequence_Size(src_lines);                               \
        for (i = 0; i < len; i++) {                                     \
            src_obj = PySequence_GetItem(src_lines, i);                 \
            FMT_OBJ_AND_APPEND(dst_fmt_tuples, NULL, src_obj, level, fail); \
            Py_DECREF(src_obj);                                         \
        }                                                               \
        Py_CLEAR(src_lines);                                            \
    }                                                                   \
}

#define CALL_FORMAT_LINES_AND_APPEND(dst_fmt_tuples, obj, level, fail)  \
{                                                                       \
    PyObject *obj_line_fmt_tuples;                                      \
                                                                        \
    if ((obj_line_fmt_tuples =                                          \
         PyObject_CallMethod(obj, "format_lines",                       \
                             "(i)", level)) == NULL) {                  \
        goto fail;                                                      \
    }                                                                   \
                                                                        \
    APPEND_LINE_TUPLES_AND_CLEAR(dst_fmt_tuples, obj_line_fmt_tuples, fail); \
}


#define APPEND_OBJ_TO_HEX_LINES_AND_CLEAR(dst_fmt_tuples, obj, level, fail) \
{                                                                       \
    PyObject *obj_lines;                                                \
                                                                        \
    if ((obj_lines = obj_to_hex(obj, OCTETS_PER_LINE_DEFAULT,           \
                                HEX_SEPARATOR_DEFAULT)) == NULL) {      \
        goto fail;                                                      \
    }                                                                   \
    Py_CLEAR(obj);                                                      \
    APPEND_LINES_AND_CLEAR(dst_fmt_tuples, obj_lines, level, fail);     \
}

#define FMT_SEC_INT_OBJ_APPEND_AND_CLEAR(dst_fmt_tuples, label, obj, level, fail) \
{                                                                       \
    PyObject *obj_lines = NULL;                                         \
    SecItem *item = (SecItem *)obj;                                     \
                                                                        \
    FMT_LABEL_AND_APPEND(dst_fmt_tuples, label, level, fail);           \
    if ((obj_lines = secitem_integer_format_lines(&item->item, level+1)) == NULL) { \
        goto fail;                                                      \
    }                                                                   \
    Py_CLEAR(obj);                                                      \
    APPEND_LINE_TUPLES_AND_CLEAR(dst_fmt_tuples, obj_lines, fail);      \
}

/******************************************************************************/

/*
 * PyBytes_From_BaseString
 *
 * param obj: Python string object
 * param encoding: Encoding to use, if NULL then utf-8
 *
 * Return: PyBytes object if successful which must be released with Py_DECREF.
 *         If unsuccessful NULL is returned and an exception will have been set.
 *
 * Convert a Python string to encoded bytes.
 *
 * Python2: The string may be either a PyUnicode or a PyString object.
 * If it's a PyString object it is assumed the value is already encoded
 * and a copy is returned.
 *
 * Python3: The string must be a PyUnicode object.
 *
 * Example:
 *
 * PyObject *encoded = NULL;
 *
 * if ((encoded = PyBytes_From_BaseString(obj, NULL)) == NULL) {
 *     return NULL;
 * }
 * some_c_function(PyBytes_AS_STRING(encoded));
 * Py_DECREF(encoded);
 */

static inline PyObject *PyBytes_From_BaseString(PyObject *obj, const char *encoding)
{
    if (!PyBaseString_Check(obj)) {
        PyErr_Format(PyExc_TypeError, "must be string, not %.50s",
                     Py_TYPE(obj)->tp_name);
        return NULL;
    }

#if PY_MAJOR_VERSION < 3
    if (PyString_Check(obj)) {
        return PyBytes_FromString(PyString_AS_STRING(obj));
    }
#endif

    return PyUnicode_AsEncodedString(obj, encoding ? encoding : "utf-8", NULL);
}

static inline void PyUnicode_ConcatAndDel(PyObject** left, PyObject* right) {
    PyObject *tmp;

    tmp = PyUnicode_Concat(*left, right);
    Py_XDECREF(*left);
    Py_XDECREF(right);
    *left = tmp;
}

static inline PyObject *
PyUnicode_Lower(PyObject *obj)
{
    PyObject *py_unicode = NULL;
    PyObject *py_lower = NULL;

    if ((py_unicode = PyUnicode_from_basestring(obj)) == NULL) {
        return NULL;
    }

    if ((py_lower = PyObject_CallMethod(obj, "lower", NULL)) == NULL) {
        Py_DECREF(py_unicode);
        return NULL;
    }

    Py_DECREF(py_unicode);
    return py_lower;
}


/******************************************************************************/

#define RETURN_COMPARE_RESULT(op, cmp_result)   \
{                                               \
    switch(op) {                                \
    case Py_LT:                                 \
        if (cmp_result < 0)                     \
            Py_RETURN_TRUE;                     \
        else                                    \
            Py_RETURN_FALSE;                    \
    case Py_LE:                                 \
        if (cmp_result <= 0)                    \
            Py_RETURN_TRUE;                     \
        else                                    \
            Py_RETURN_FALSE;                    \
    case Py_EQ:                                 \
        if (cmp_result == 0)                    \
            Py_RETURN_TRUE;                     \
        else                                    \
            Py_RETURN_FALSE;                    \
    case Py_NE:                                 \
        if (cmp_result != 0)                    \
            Py_RETURN_TRUE;                     \
        else                                    \
            Py_RETURN_FALSE;                    \
    case Py_GT:                                 \
        if (cmp_result > 0)                     \
            Py_RETURN_TRUE;                     \
        else                                    \
            Py_RETURN_FALSE;                    \
    case Py_GE:                                 \
        if (cmp_result >= 0)                    \
            Py_RETURN_TRUE;                     \
        else                                    \
            Py_RETURN_FALSE;                    \
    }                                           \
                                                \
    Py_RETURN_FALSE;                            \
}

#define Py_RETURN_BOOL(condition) {if (condition) Py_RETURN_TRUE; else Py_RETURN_FALSE;}

// Gettext
#ifndef _
#define _(s) s
#endif

#define CALL_BASE(type, func, ...) (type)->tp_base->tp_##func(__VA_ARGS__)

#define TYPE_READY(type)                                                \
{                                                                       \
    if (PyType_Ready(&type) < 0)                                        \
        return MOD_ERROR_VAL;                                           \
    Py_INCREF(&type);                                                   \
    PyModule_AddObject(m, rindex(type.tp_name, '.')+1, (PyObject *)&type); \
}

#define AddIntConstant(c)                                               \
{                                                                       \
    PyObject *dict;                                                     \
                                                                        \
                                                                        \
    if ((dict = PyModule_GetDict(m)) == NULL) {                         \
        PyErr_Format(PyExc_SystemError, "module '%s' has no __dict__",  \
                     PyModule_GetName(m));                              \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyDict_GetItemString(dict, #c)) {                               \
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s", \
                         PyModule_GetName(m), #c);                      \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyModule_AddIntConstant(m, #c, c) < 0) return MOD_ERROR_VAL;    \
}

#define AddIntConstantName(name, c)                                     \
{                                                                       \
    PyObject *dict;                                                     \
                                                                        \
                                                                        \
    if ((dict = PyModule_GetDict(m)) == NULL) {                         \
        PyErr_Format(PyExc_SystemError, "module '%s' has no __dict__",  \
                     PyModule_GetName(m));                              \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyDict_GetItemString(dict, #c)) {                               \
        PyErr_Format(PyExc_SystemError, "module '%s' already contains %s", \
                         PyModule_GetName(m), #c);                      \
        return MOD_ERROR_VAL;                                           \
    }                                                                   \
    if (PyModule_AddIntConstant(m, #name, c) < 0) return MOD_ERROR_VAL; \
}

#ifdef DEBUG

#define DumpRefCount(x)                                                 \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    printf("<%s object at %p refcnt=%d>\n", Py_TYPE(_obj)->tp_name, _obj, _obj->ob_refcnt); \
}


#define TraceMessage(_msg)                      \
{                                               \
    printf("%s\n", _msg);                       \
}

#define TraceMethodEnter(x)                                             \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    const char *name = NULL;                                            \
                                                                        \
    if (_obj) {                                                         \
        name = Py_TYPE(_obj)->tp_name;                                  \
    }                                                                   \
    printf("%s (Enter): <%s object at %p refcnt=%d>\n",                 \
           __FUNCTION__, name, _obj, _obj ? _obj->ob_refcnt : -9999);   \
}

#define TraceMethodLeave(x)                                             \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    const char *name = NULL;                                            \
                                                                        \
    if (_obj) {                                                         \
        name = Py_TYPE(_obj)->tp_name;                                  \
    }                                                                   \
    printf("%s (Leave): <%s object at %p refcnt=%d>\n",                 \
           __FUNCTION__, name, _obj, _obj ? _obj->ob_refcnt : -9999);   \
}

#define TraceObjNewEnter(_tp)                                   \
{                                                               \
    PyTypeObject *tp = _tp;                                     \
    if (tp != NULL)                                             \
        printf("%s (Enter) %s\n", __FUNCTION__, tp->tp_name);   \
    else                                                        \
        printf("%s (Enter)\n", __FUNCTION__);                   \
}


#define TraceObjNewLeave(x)                                             \
{                                                                       \
    PyObject *_obj = (PyObject *) (x);                                  \
    const char *name = NULL;                                            \
                                                                        \
    if (_obj) {                                                         \
        name = Py_TYPE(_obj)->tp_name;                                  \
    }                                                                   \
    printf("%s: returns <%s object at %p refcnt=%d>\n",                 \
           __FUNCTION__, name, _obj, _obj ? _obj->ob_refcnt : -9999);   \
}

#else
#define DumpRefCount(_obj)
#define TraceMessage(_msg)
#define TraceMethodEnter(_obj)
#define TraceMethodLeave(_obj)
#define TraceObjNewEnter(_tp)
#define TraceObjNewLeave(_obj)
#endif
