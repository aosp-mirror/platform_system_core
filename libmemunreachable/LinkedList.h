/*
 * Copyright (C) 2016 The Android Open Source Project
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

#ifndef LIBMEMUNREACHABLE_LINKED_LIST_H_
#define LIBMEMUNREACHABLE_LINKED_LIST_H_

namespace android {

template <class T>
class LinkedList {
 public:
  LinkedList() : next_(this), prev_(this), data_() {}
  explicit LinkedList(T data) : LinkedList() { data_ = data; }
  ~LinkedList() {}
  void insert(LinkedList<T>& node) {
    assert(node.empty());
    node.next_ = this->next_;
    node.next_->prev_ = &node;
    this->next_ = &node;
    node.prev_ = this;
  }
  void remove() {
    this->next_->prev_ = this->prev_;
    this->prev_->next_ = this->next_;
    this->next_ = this;
    this->prev_ = this;
  }
  T data() { return data_; }
  bool empty() { return next_ == this && prev_ == this; }
  LinkedList<T>* next() { return next_; }

 private:
  LinkedList<T>* next_;
  LinkedList<T>* prev_;
  T data_;
};

template <class T>
class LinkedListHead {
 public:
  LinkedListHead() : node_() {}
  ~LinkedListHead() {}

 private:
  LinkedList<T> node_;
};

}  // namespace android

#endif
