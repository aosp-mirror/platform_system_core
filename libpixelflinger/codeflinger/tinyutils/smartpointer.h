/*
 * Copyright 2005 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_PIXELFLINGER_SMART_POINTER_H
#define ANDROID_PIXELFLINGER_SMART_POINTER_H

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>

// ---------------------------------------------------------------------------
namespace android {
namespace tinyutils {

// ---------------------------------------------------------------------------

#define COMPARE(_op_)                                           \
inline bool operator _op_ (const sp<T>& o) const {              \
    return m_ptr _op_ o.m_ptr;                                  \
}                                                               \
inline bool operator _op_ (const T* o) const {                  \
    return m_ptr _op_ o;                                        \
}                                                               \
template<typename U>                                            \
inline bool operator _op_ (const sp<U>& o) const {              \
    return m_ptr _op_ o.m_ptr;                                  \
}                                                               \
template<typename U>                                            \
inline bool operator _op_ (const U* o) const {                  \
    return m_ptr _op_ o;                                        \
}

// ---------------------------------------------------------------------------

template <typename T>
class sp
{
public:
    inline sp() : m_ptr(0) { }

    sp(T* other);  // NOLINT, implicit
    sp(const sp<T>& other);
    template<typename U> sp(U* other);  // NOLINT, implicit
    template<typename U> sp(const sp<U>& other);  // NOLINT, implicit

    ~sp();
    
    // Assignment

    sp& operator = (T* other);
    sp& operator = (const sp<T>& other);
    
    template<typename U> sp& operator = (const sp<U>& other);
    template<typename U> sp& operator = (U* other);
    
    // Reset
    void clear();
    
    // Accessors

    inline  T&      operator* () const  { return *m_ptr; }
    inline  T*      operator-> () const { return m_ptr;  }
    inline  T*      get() const         { return m_ptr; }

    // Operators
        
    COMPARE(==)
    COMPARE(!=)
    COMPARE(>)
    COMPARE(<)
    COMPARE(<=)
    COMPARE(>=)

private:    
    template<typename Y> friend class sp;

    T*              m_ptr;
};

// ---------------------------------------------------------------------------
// No user serviceable parts below here.

template<typename T>
sp<T>::sp(T* other)
    : m_ptr(other)
{
    if (other) other->incStrong(this);
}

template<typename T>
sp<T>::sp(const sp<T>& other)
    : m_ptr(other.m_ptr)
{
    if (m_ptr) m_ptr->incStrong(this);
}

template<typename T> template<typename U>
sp<T>::sp(U* other) : m_ptr(other)
{
    if (other) other->incStrong(this);
}

template<typename T> template<typename U>
sp<T>::sp(const sp<U>& other)
    : m_ptr(other.m_ptr)
{
    if (m_ptr) m_ptr->incStrong(this);
}

template<typename T>
sp<T>::~sp()
{
    if (m_ptr) m_ptr->decStrong(this);
}

template<typename T>
sp<T>& sp<T>::operator = (const sp<T>& other) {
    if (other.m_ptr) other.m_ptr->incStrong(this);
    if (m_ptr) m_ptr->decStrong(this);
    m_ptr = other.m_ptr;
    return *this;
}

template<typename T>
sp<T>& sp<T>::operator = (T* other)
{
    if (other) other->incStrong(this);
    if (m_ptr) m_ptr->decStrong(this);
    m_ptr = other;
    return *this;
}

template<typename T> template<typename U>
sp<T>& sp<T>::operator = (const sp<U>& other)
{
    if (other.m_ptr) other.m_ptr->incStrong(this);
    if (m_ptr) m_ptr->decStrong(this);
    m_ptr = other.m_ptr;
    return *this;
}

template<typename T> template<typename U>
sp<T>& sp<T>::operator = (U* other)
{
    if (other) other->incStrong(this);
    if (m_ptr) m_ptr->decStrong(this);
    m_ptr = other;
    return *this;
}

template<typename T>
void sp<T>::clear()
{
    if (m_ptr) {
        m_ptr->decStrong(this);
        m_ptr = 0;
    }
}

// ---------------------------------------------------------------------------

} // namespace tinyutils
} // namespace android

// ---------------------------------------------------------------------------

#endif // ANDROID_PIXELFLINGER_SMART_POINTER_H
