// taken from https://github.com/yuki-koyama/parallel-util/

/*
MIT License

Copyright (c) 2018 Yuki Koyama

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

/// \file parallel-util.hpp

#ifndef parallel_util_hpp
#define parallel_util_hpp

// Uncommenting the following line enables the "verbose" mode, which may be
// useful for debugging. However, notice that it affects the overall performance
// badly as it inserts mutex-locked standard output commands.

// #define PARALLELUTIL_VERBOSE

#include <spdlog/spdlog.h>

#include <functional>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>
#ifdef PARALLELUTIL_VERBOSE
#include <iostream>
#endif

namespace parallelutil
{
    /// \brief Execute a for-loop process for an array in parallel
    /// \param n The number of iterations. I.e., { 0, 1, ..., n - 1 } will be visited.
    /// \param function The function that will be called in the for-loop. This can be specified as a lambda expression. The type should be equivalent to std::function<void(int)>.
    /// \param target_concurrency The number of threads that will be generated. When this is set to zero (which is the default), the hardware concurrency will be automatically used.
    template<typename Callable>
    void parallel_for(int n, Callable function, int target_concurrency = 0)
    {
        const int hint      = (target_concurrency == 0) ? std::thread::hardware_concurrency() : target_concurrency;
        const int n_threads = std::min<int>(n, (hint == 0) ? 4 : hint);
#ifdef PARALLELUTIL_VERBOSE
        std::mutex io_mutex;
#endif

        const int n_max_tasks_per_thread = (n / n_threads) + (n % n_threads == 0 ? 0 : 1);
        const int n_lacking_tasks        = n_max_tasks_per_thread * n_threads - n;

        auto inner_loop = [&](const int thread_index)
        {
            const int n_lacking_tasks_so_far = std::max<int>(thread_index - n_threads + n_lacking_tasks, 0);
            const int inclusive_start_index  = thread_index * n_max_tasks_per_thread - n_lacking_tasks_so_far;
            const int exclusive_end_index    = inclusive_start_index + n_max_tasks_per_thread - (thread_index - n_threads + n_lacking_tasks >= 0 ? 1 : 0);

            for (int k = inclusive_start_index; k < exclusive_end_index; ++ k)
            {
#ifdef PARALLELUTIL_VERBOSE
                io_mutex.lock();
                std::cout << "parallel-util ... Thread " << thread_index + 1 << ": " << k - inclusive_start_index + 1 << " / " << exclusive_end_index - inclusive_start_index << std::endl;
                io_mutex.unlock();
#endif
                function(k);
            }
#ifdef PARALLELUTIL_VERBOSE
            io_mutex.lock();
            std::cout << "parallel-util ... Thread " << thread_index + 1 << ": done" << std::endl;
            io_mutex.unlock();
#endif
        };
        std::vector<std::unique_ptr<std::thread>> threads{};
        threads.reserve(n_threads);
        for (int j = 0; j < n_threads; ++ j) { threads.push_back(std::make_unique<std::thread>(inner_loop, j)); }
        for (auto& t : threads) try { if (t->joinable()) t->join(); } catch(...) { spdlog::error("Exception occurred trying to join a thread"); } // do we not care? lets find out.
    }

    template<typename N, typename Callable>
    void parallel_for(N begin, N end, N step, Callable function, int target_concurrency = 0)
    {
        const auto n = (end - begin) / step;
        parallel_for(n, [&](int i) { function(begin + (N)i * step); }, target_concurrency);
    }

    template<typename N, typename Callable>
    void parallel_for(N begin, N end, Callable function, int target_concurrency = 0)
    {
        parallel_for<N, Callable>(begin, end, 1, function, target_concurrency);
    }

    /// \brief Execute a for-loop process for a 2D array (e.g., a bitmap image data) in parallel
    /// \param width The width of the target 2D array. I.e., { 0, 1, ..., width - 1 } will be visited as the first dimensional indices.
    /// \param height The height of the target 2D array. I.e., { 0, 1, ..., height - 1 } will be visited as the second dimensional indices.
    /// \param function The function that will be called in the for-loop. This can be specified as a lambda expression. The type should be equivalent to std::function<void(int, int)>.
    /// \param target_concurrency The number of threads that will be generated. When this is set to zero (which is the default), the hardware concurrency will be automatically used.
    template<typename Callable>
    void parallel_for_2d(int width, int height, Callable function, int target_concurrency = 0)
    {
        const int hint      = (target_concurrency == 0) ? std::thread::hardware_concurrency() : target_concurrency;
        const int n_threads = std::min<int>(width * height, (hint == 0) ? 4 : hint);

        auto inner_loop = [width, height, n_threads, function](const int thread_index)
        {
            const int n = width * height;

            const int start_index = thread_index * (n / n_threads);
            const int end_index   = (thread_index + 1 == n_threads) ? n : (thread_index + 1) * (n / n_threads);

            for (int k = start_index; k < end_index; ++ k) { function(k % width, k / width); }
        };
        std::vector<std::thread> threads;
        for (int j = 0; j < n_threads; ++ j) { threads.push_back(std::thread(inner_loop, j)); }
        for (auto& t : threads) { t.join(); }
    }

    /// \brief Execute a for-loop process for an array in parallel based on a task queue
    /// \param n The number of iterations. I.e., { 0, 1, ..., n - 1 } will be visited.
    /// \param function The function that will be called in the for-loop. This can be specified as a lambda expression. The type should be equivalent to std::function<void(int)>.
    /// \param target_concurrency The number of threads that will be generated. When this is set to zero (which is the default), the hardware concurrency will be automatically used.
    /// \details Compared to parallel_for(), this function is likely to achieve better CPU occupancy especially when the cost of each local process is computationally heterogenous (i.e., some processes are light and others are heavy). However, this function could be slower than parallel_for() in some cases because of (1) cache inefficiency (each thread works on less local processes) and (2) mutex lock for the task queue.
    template<typename Callable>
    void queue_based_parallel_for(int n, Callable function, int target_concurrency = 0)
    {
        const int hint      = (target_concurrency == 0) ? std::thread::hardware_concurrency() : target_concurrency;
        const int n_threads = std::min<int>(n, (hint == 0) ? 4 : hint);

        // Mutex object for queue manipulation
        std::mutex queue_mutex;

#ifdef PARALLELUTIL_VERBOSE
        // Mutex object for IO
        std::mutex io_mutex;
#endif

        std::queue<int> task_queue;
        for (int i = 0; i < n; ++ i) { task_queue.push(i); }

        auto thread_routine = [&](const int thread_index)
        {
            while (true)
            {
                queue_mutex.lock();

                if (task_queue.empty()) { queue_mutex.unlock(); break; }

                const int task_index = task_queue.front();
                task_queue.pop();

                queue_mutex.unlock();

#ifdef PARALLELUTIL_VERBOSE
                io_mutex.lock();
                std::cout << "parallel-util ... Thread " << thread_index + 1 << ": " << task_index + 1 << " / " << n << std::endl;
                io_mutex.unlock();
#endif

                function(task_index);
            }

#ifdef PARALLELUTIL_VERBOSE
            io_mutex.lock();
            std::cout << "parallel-util ... Thread " << thread_index + 1 << ": done" << std::endl;
            io_mutex.unlock();
#endif
        };
        std::vector<std::thread> threads;
        for (int j = 0; j < n_threads; ++ j) { threads.push_back(std::thread(thread_routine, j)); }
        for (auto& t : threads) { t.join(); }
    }

    /// \brief Execute "map" operation to an array in parallel
    /// \param input_array The array that will be processed by map operation.
    /// \param function The function that will be used for map operation. It can be specified as a lambda expression. It should take a single input variable whose type is T and returns a non-void class instance etc.
    /// \return An array of resulting instances.
    template<typename T, typename Callable>
    auto parallel_map(const std::vector<T>& input_array, Callable function, int target_concurrency = 0)
#if __cplusplus < 201402L
    -> std::vector<decltype(function(input_array.front()))>
#endif
    {
        std::vector<decltype(function(input_array.front()))> result_array(input_array.size());
        auto indexed_function = [&](int index) { result_array[index] = function(input_array[index]); };
        queue_based_parallel_for(input_array.size(), indexed_function);
        return result_array;
    }

    /// \brief Execute a set of processes in parallel
    inline void parallel_exec(const std::vector<std::function<void()>>& functions)
    {
        queue_based_parallel_for(functions.size(), [&](int index) { functions[index](); });
    }
}

#endif /* parallel_util_hpp */
